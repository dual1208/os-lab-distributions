package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/datapath"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
)

const (
	relayConnectWindow = 10 * time.Second
	relayRetryInitial  = 250 * time.Millisecond
	relayRetryMaximum  = 5 * time.Second
)

type relayPathCandidate struct {
	connection datapath.Connection
	peer       identity.Verified
	cutoff     time.Time
	liveness   context.Context
	state      *relayCandidateState
	now        func() time.Time
}

type relayCandidateState struct {
	expired bool
}

// superviseRelay keeps one validated warm-relay slot available for the data
// lifetime. The reconnect closure owns all network authentication and returns
// only a connection eligible for atomic mux installation.
func (r *Runner) superviseRelay(
	ctx context.Context,
	mux *datapath.Mux,
	reconnect func(context.Context) (relayPathCandidate, error),
) error {
	if r == nil || ctx == nil || mux == nil || reconnect == nil || mux.RelayRecoveryNeeded() == nil {
		return errors.New("relay recovery dependencies unavailable")
	}
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-mux.RelayRecoveryNeeded():
		}
		if mux.Snapshot().RelayHealthy {
			continue
		}

		attempt := uint(0)
		for !mux.Snapshot().RelayHealthy {
			candidate, err := reconnect(ctx)
			if err == nil && (candidate.connection == nil || sanitizedCertificateStatus(candidate.peer) == nil) {
				err = errors.New("relay reconnect returned no connection")
			}
			if err == nil {
				if mux.Snapshot().RelayHealthy {
					_ = candidate.connection.Close("redundant relay replacement")
					break
				}
				_, err = r.commitRelayCandidate(mux, candidate)
				if err == nil {
					break
				}
			}
			if candidate.connection != nil {
				_ = candidate.connection.Close("relay replacement rejected")
			}
			if errors.Is(err, datapath.ErrClosed) || errors.Is(err, datapath.ErrInstanceIDExhausted) {
				return err
			}
			if ctx.Err() != nil {
				return context.Cause(ctx)
			}
			log.Printf("warm relay unavailable; bounded retry scheduled")
			delay := jitterRetryDelay(controlRetryDelay(attempt, relayRetryInitial, relayRetryMaximum), nil)
			if err := waitControlRetry(ctx, delay); err != nil {
				return err
			}
			if attempt < ^uint(0) {
				attempt++
			}
		}
	}
}

// openRelayConnection creates and fully validates an edge-to-edge QUIC
// connection whose observed transport path is the authenticated relay tuple.
func (r *Runner) openRelayConnection(
	ctx context.Context,
	transport *quic.Transport,
	acceptor *quicAcceptDispatcher,
	dataTLS *tls.Config,
	quicConfig *quic.Config,
	relayUDP *net.UDPAddr,
	localData identity.Verified,
) (relayPathCandidate, error) {
	if r == nil || ctx == nil || dataTLS == nil || quicConfig == nil || relayUDP == nil {
		return relayPathCandidate{}, errors.New("relay connection dependencies unavailable")
	}
	relayTuple := relayUDP.AddrPort()
	if !relayTuple.IsValid() {
		return relayPathCandidate{}, errors.New("relay tuple unavailable")
	}
	attemptCtx, cancelAttempt := context.WithTimeout(ctx, relayConnectWindow)
	defer cancelAttempt()

	var connection *quic.Conn
	var err error
	if r.cfg.Site == "site-a" {
		if transport == nil {
			return relayPathCandidate{}, errors.New("relay transport unavailable")
		}
		connection, err = transport.Dial(attemptCtx, relayUDP, dataTLS.Clone(), quicConfig)
	} else {
		if acceptor == nil {
			return relayPathCandidate{}, errors.New("relay accept classifier unavailable")
		}
		connection, err = acceptor.AcceptRelay(attemptCtx)
	}
	if err != nil {
		return relayPathCandidate{}, err
	}
	reject := func(reason string, err error) (relayPathCandidate, error) {
		_ = connection.CloseWithError(directCloseCode, reason)
		return relayPathCandidate{}, err
	}
	if !sameDirectAddress(connection.RemoteAddr(), relayTuple) {
		return reject("relay tuple rejected", errors.New("relay tuple classification rejected"))
	}
	if err := validateDatagramConnection(connection, r.cfg.MTU+datapath.WireOverhead); err != nil {
		return reject("relay DATAGRAM capacity rejected", err)
	}
	peerData, err := identity.VerifyConnection(connection.ConnectionState().TLS, r.dataRequirements)
	if err != nil {
		return reject("relay peer identity rejected", err)
	}
	cutoff, err := identity.SessionDeadline(time.Now(), localData, peerData)
	if err != nil {
		return reject("relay certificate lifetime rejected", err)
	}

	relayConnection := &quicDataConnection{Conn: connection}
	candidateState := &relayCandidateState{}
	if _, err := identity.GuardCertificateCutoff(connection.Context(), cutoff, func() {
		r.mu.Lock()
		candidateState.expired = true
		r.mu.Unlock()
		_ = relayConnection.Close("relay certificate rotation")
	}); err != nil {
		return reject("relay certificate cutoff rejected", err)
	}
	return relayPathCandidate{
		connection: relayConnection, peer: peerData, cutoff: cutoff,
		liveness: connection.Context(), state: candidateState,
	}, nil
}

// commitRelayCandidate serializes final cutoff/liveness validation, exact-ID
// identity publication, and mux replacement under Runner.mu. The mux invokes
// the binding callback under its own state lock, preserving Runner->Mux order.
func (r *Runner) commitRelayCandidate(mux *datapath.Mux, candidate relayPathCandidate) (uint64, error) {
	if r == nil || mux == nil {
		return 0, errors.New("relay commit authority unavailable")
	}
	r.mu.Lock()
	if err := candidate.validateLocked(); err != nil {
		r.mu.Unlock()
		if candidate.connection != nil {
			_ = candidate.connection.Close("relay replacement expired before commit")
		}
		return 0, err
	}
	instanceID, err := mux.ReplaceRelayWithBinding(candidate.connection, func(id uint64) {
		r.bindPathIdentityMapLocked(mux, datapath.SelectedRelay, id, candidate.peer)
	})
	if err == nil && r.pathMux == mux {
		r.refreshStatusTransitionsLocked()
	}
	r.mu.Unlock()
	return instanceID, err
}

func (candidate relayPathCandidate) validateLocked() error {
	if candidate.connection == nil || candidate.state == nil || candidate.liveness == nil || candidate.cutoff.IsZero() ||
		candidate.state.expired || candidate.liveness.Err() != nil {
		return identity.ErrCertificateCutoff
	}
	now := time.Now
	if candidate.now != nil {
		now = candidate.now
	}
	observed := now()
	if observed.IsZero() || !observed.Before(candidate.cutoff) {
		return identity.ErrCertificateCutoff
	}
	return nil
}

func (r *Runner) newRelayMux(
	ctx context.Context, mtu int, candidate relayPathCandidate,
) (*datapath.Mux, error) {
	if r == nil {
		return nil, errors.New("relay commit authority unavailable")
	}
	r.mu.Lock()
	r.refreshStatusTransitionsLocked()
	if err := candidate.validateLocked(); err != nil {
		r.mu.Unlock()
		if candidate.connection != nil {
			_ = candidate.connection.Close("initial relay expired before commit")
		}
		return nil, err
	}
	mux, err := datapath.NewDirectRequired(ctx, mtu, candidate.connection)
	if err == nil {
		snapshot := mux.Snapshot()
		r.bindPathIdentityMapLocked(mux, datapath.SelectedRelay, snapshot.RelayInstanceID, candidate.peer)
		r.pathMux = mux
		r.refreshStatusTransitionsLocked()
	}
	r.mu.Unlock()
	return mux, err
}
