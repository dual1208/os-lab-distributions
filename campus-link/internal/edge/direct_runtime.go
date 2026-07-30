package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/datapath"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/direct"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/rendezvous"
)

const directCloseCode quic.ApplicationErrorCode = 0x434c

const (
	directRetryInitial = 250 * time.Millisecond
	directRetryMaximum = 5 * time.Second
)

type directAttemptResult struct {
	plan           authorizedPlan
	connectionDone <-chan struct{}
	err            error
}

func (r *Runner) directWorker(
	ctx context.Context,
	transport *quic.Transport,
	probeIO rendezvous.NonQUICPacketIO,
	acceptor *quicAcceptDispatcher,
	dataTLS *tls.Config,
	quicConfig *quic.Config,
	mux *datapath.Mux,
	localData identity.Verified,
) {
	replay := rendezvous.NewReplayCache(1024)
	var current *authorizedPlan
	var attemptDone <-chan directAttemptResult
	var cancelAttempt context.CancelFunc
	var activeDone <-chan struct{}
	var activeEpoch uint64
	var activeLease planSessionLease
	var retryTimer *time.Timer
	var retryReady <-chan time.Time
	retryCount := uint(0)
	stopRetry := func() {
		if retryTimer != nil {
			retryTimer.Stop()
		}
		retryTimer = nil
		retryReady = nil
	}
	scheduleRetry := func() {
		stopRetry()
		if current == nil || !time.Now().Before(current.Expires) ||
			!r.planAuthorityCurrent(current.lease, current.PathEpoch) {
			return
		}
		delay := jitterRetryDelay(controlRetryDelay(retryCount, directRetryInitial, directRetryMaximum), nil)
		retryCount++
		remaining := time.Until(current.Expires)
		if delay > remaining {
			delay = remaining
		}
		if delay <= 0 {
			return
		}
		retryTimer = time.NewTimer(delay)
		retryReady = retryTimer.C
	}
	defer stopRetry()
	for {
		if attemptDone == nil && retryReady == nil && current != nil && time.Now().Before(current.Expires) {
			snapshot := mux.Snapshot()
			needsAttempt := !snapshot.DirectHealthy || snapshot.DirectEpoch < current.PathEpoch
			if needsAttempt && r.planAuthorityCurrent(current.lease, current.PathEpoch) {
				plan := *current
				attemptCtx, cancel := planAttemptContext(ctx, plan.lease, plan.Expires)
				cancelAttempt = cancel
				result := make(chan directAttemptResult, 1)
				attemptDone = result
				go func() {
					connectionDone, err := r.runDirectAttempt(
						attemptCtx, ctx, transport, probeIO, acceptor, dataTLS, quicConfig, mux, localData, replay, plan.Plan, plan.lease,
					)
					result <- directAttemptResult{plan: plan, connectionDone: connectionDone, err: err}
				}()
			}
		}
		select {
		case <-ctx.Done():
			if cancelAttempt != nil {
				cancelAttempt()
			}
			return
		case plan := <-r.plans:
			if activeDone != nil {
				activeLease = rebindActivePlanLease(current, plan, activeEpoch, activeLease)
			}
			if cancelAttempt != nil {
				cancelAttempt()
			}
			stopRetry()
			copyOfPlan := plan
			current = &copyOfPlan
			retryCount = 0
		case result := <-attemptDone:
			if cancelAttempt != nil {
				cancelAttempt()
			}
			cancelAttempt = nil
			attemptDone = nil
			if current == nil || result.plan.PathEpoch != current.PathEpoch ||
				!samePlanSession(result.plan.lease, current.lease) ||
				!r.planAuthorityCurrent(result.plan.lease, result.plan.PathEpoch) {
				continue
			}
			if result.err != nil {
				r.directFailures.Add(1)
				if !mux.Snapshot().DirectHealthy {
					r.setDirectAttempt("failed")
				}
				log.Printf("direct path attempt failed")
				scheduleRetry()
				continue
			}
			activeDone = result.connectionDone
			activeEpoch = result.plan.PathEpoch
			activeLease = result.plan.lease
			retryCount = 0
		case <-activeDone:
			activeDone = nil
			if r.activePlanRetryEligible(current, activeEpoch, activeLease) {
				scheduleRetry()
			}
		case <-retryReady:
			retryTimer = nil
			retryReady = nil
		}
	}
}

func rebindActivePlanLease(
	current *authorizedPlan,
	incoming authorizedPlan,
	activeEpoch uint64,
	activeLease planSessionLease,
) planSessionLease {
	// Keep the independently authenticated connection and its close channel in
	// place. Only the authority consulted when that channel later closes moves
	// to the fresh lease, and only for the exact plan in the same namespace.
	if !incoming.leaseRebind || current == nil || activeEpoch == 0 || activeEpoch != incoming.PathEpoch ||
		!samePlanSession(activeLease, current.lease) || current.lease.namespace != incoming.lease.namespace ||
		!sameValidatedPlan(current.Plan, incoming.Plan) {
		return activeLease
	}
	return incoming.lease
}

func (r *Runner) activePlanRetryEligible(
	current *authorizedPlan,
	activeEpoch uint64,
	activeLease planSessionLease,
) bool {
	return current != nil && activeEpoch == current.PathEpoch &&
		samePlanSession(activeLease, current.lease) && r.planAuthorityCurrent(activeLease, activeEpoch)
}

func (r *Runner) runDirectAttempt(
	ctx, lifetimeCtx context.Context,
	transport *quic.Transport,
	probeIO rendezvous.NonQUICPacketIO,
	acceptor *quicAcceptDispatcher,
	dataTLS *tls.Config,
	quicConfig *quic.Config,
	mux *datapath.Mux,
	localData identity.Verified,
	replay *rendezvous.ReplayCache,
	plan rendezvous.Plan,
	lease planSessionLease,
) (<-chan struct{}, error) {
	if !r.planAuthorityCurrent(lease, plan.PathEpoch) {
		return nil, datapath.ErrStalePath
	}
	r.setDirectAttempt("punching")
	punchSession, err := rendezvous.PunchCandidatesNonQUIC(ctx, probeIO, plan, r.cfg.Site, nil, replay)
	if err != nil {
		return nil, err
	}
	defer punchSession.Stop()
	peerAddresses := punchSession.Candidates()
	if !r.planAuthorityCurrent(lease, plan.PathEpoch) {
		return nil, datapath.ErrStalePath
	}
	r.setDirectAttempt("handshaking")
	connection, stream, result, peer, err := r.establishDirect(ctx, transport, acceptor, dataTLS, quicConfig, plan, peerAddresses)
	if err != nil {
		return nil, err
	}
	if err := r.activateDirect(ctx, lifetimeCtx, mux, connection, stream, result, plan, lease, localData, peer); err != nil {
		_ = stream.Close()
		_ = connection.CloseWithError(directCloseCode, "direct activation rejected")
		return nil, err
	}
	return connection.Context().Done(), nil
}

func (r *Runner) establishDirect(
	ctx context.Context,
	transport *quic.Transport,
	acceptor *quicAcceptDispatcher,
	dataTLS *tls.Config,
	quicConfig *quic.Config,
	plan rendezvous.Plan,
	peerAddresses []netip.AddrPort,
) (*quic.Conn, direct.Stream, direct.Result, identity.Verified, error) {
	if transport == nil || dataTLS == nil || quicConfig == nil || len(peerAddresses) == 0 {
		return nil, nil, direct.Result{}, identity.Verified{}, errors.New("direct path runtime unavailable")
	}
	for _, peerAddress := range peerAddresses {
		if !peerAddress.IsValid() {
			return nil, nil, direct.Result{}, identity.Verified{}, errors.New("direct path candidate unavailable")
		}
	}
	if r.cfg.Site == "site-a" {
		var failures []error
		for _, peerAddress := range peerAddresses {
			dialCtx, cancelDial := context.WithTimeout(ctx, 5*time.Second)
			connection, err := transport.Dial(dialCtx, net.UDPAddrFromAddrPort(peerAddress), dataTLS.Clone(), quicConfig)
			cancelDial()
			if err != nil {
				failures = append(failures, err)
				continue
			}
			if err := validateDatagramConnection(connection, r.cfg.MTU+datapath.WireOverhead); err != nil {
				_ = connection.CloseWithError(directCloseCode, "direct identity rejected")
				failures = append(failures, err)
				continue
			}
			boundPlan, peer, err := direct.BindTLSExporter(plan, r.cfg.Site, connection.ConnectionState().TLS, r.dataRequirements)
			if err != nil {
				_ = connection.CloseWithError(directCloseCode, "direct exporter rejected")
				failures = append(failures, err)
				continue
			}
			stream, err := connection.OpenStreamSync(ctx)
			if err != nil {
				_ = connection.CloseWithError(directCloseCode, "direct stream unavailable")
				failures = append(failures, err)
				continue
			}
			result, err := direct.Initiate(ctx, stream, boundPlan, r.cfg.Site, nil, direct.Options{})
			if err != nil {
				_ = stream.Close()
				_ = connection.CloseWithError(directCloseCode, "direct authentication rejected")
				failures = append(failures, err)
				continue
			}
			return connection, stream, result, peer, nil
		}
		return nil, nil, direct.Result{}, identity.Verified{}, errors.Join(failures...)
	}
	if acceptor == nil {
		return nil, nil, direct.Result{}, identity.Verified{}, errors.New("direct accept classifier unavailable")
	}
	for {
		connection, err := acceptor.AcceptDirect(ctx, peerAddresses)
		if err != nil {
			return nil, nil, direct.Result{}, identity.Verified{}, err
		}
		if !sameDirectAddressAny(connection.RemoteAddr(), peerAddresses) {
			_ = connection.CloseWithError(directCloseCode, "unexpected direct source")
			continue
		}
		if err := validateDatagramConnection(connection, r.cfg.MTU+datapath.WireOverhead); err != nil {
			_ = connection.CloseWithError(directCloseCode, "direct identity rejected")
			continue
		}
		boundPlan, peer, err := direct.BindTLSExporter(plan, r.cfg.Site, connection.ConnectionState().TLS, r.dataRequirements)
		if err != nil {
			_ = connection.CloseWithError(directCloseCode, "direct exporter rejected")
			continue
		}
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			_ = connection.CloseWithError(directCloseCode, "direct stream unavailable")
			continue
		}
		result, err := direct.Accept(ctx, stream, boundPlan, r.cfg.Site, nil, direct.Options{})
		if err != nil {
			_ = stream.Close()
			_ = connection.CloseWithError(directCloseCode, "direct authentication rejected")
			continue
		}
		return connection, stream, result, peer, nil
	}
}

func sameDirectAddressAny(address net.Addr, expected []netip.AddrPort) bool {
	for _, candidate := range expected {
		if sameDirectAddress(address, candidate) {
			return true
		}
	}
	return false
}

func (r *Runner) activateDirect(
	ctx, lifetimeCtx context.Context,
	mux *datapath.Mux,
	connection *quic.Conn,
	stream direct.Stream,
	result direct.Result,
	plan rendezvous.Plan,
	lease planSessionLease,
	localData, peerData identity.Verified,
) error {
	cutoff, err := identity.SessionDeadline(time.Now(), localData, peerData)
	if err != nil {
		_ = connection.CloseWithError(directCloseCode, "direct certificate lifetime rejected")
		return err
	}
	if !r.planAuthorityCurrent(lease, plan.PathEpoch) {
		return datapath.ErrStalePath
	}
	deliveryMonitor, err := direct.NewDeliveryMonitor(stream, result, r.cfg.Site, direct.MonitorOptions{})
	if err != nil {
		return err
	}
	dataConnection := &quicDataConnection{Conn: connection, delivery: deliveryMonitor}
	activation := &muxActivation{
		runner: r, mux: mux, connection: dataConnection, epoch: plan.PathEpoch, lease: lease, cutoff: cutoff,
		peerData: peerData,
	}
	cutoffGuard, err := identity.GuardCertificateCutoff(connection.Context(), cutoff, activation.expireCutoff)
	if err != nil {
		_ = connection.CloseWithError(directCloseCode, "direct certificate cutoff rejected")
		return err
	}
	activation.cutoffGuard = cutoffGuard
	if r.cfg.Site == "site-a" {
		err = direct.ActivateInitiator(ctx, stream, result, activation)
	} else {
		err = direct.ActivateReceiver(ctx, stream, result, activation)
	}
	if err != nil {
		cutoffGuard.Stop()
		_ = connection.CloseWithError(directCloseCode, "stale direct path")
		return err
	}
	if err := dataConnection.StartDelivery(connection.Context()); err != nil {
		cutoffGuard.Stop()
		dataConnection.FailDelivery()
		_ = connection.CloseWithError(directCloseCode, "direct progress monitor rejected")
		return err
	}
	r.setDirectAttempt("active")
	go func() {
		select {
		case <-lifetimeCtx.Done():
			_ = connection.CloseWithError(directCloseCode, "direct plan ended")
		case <-connection.Context().Done():
		}
	}()
	return nil
}

type muxActivation struct {
	runner        *Runner
	mux           *datapath.Mux
	connection    datapath.Connection
	epoch         uint64
	lease         planSessionLease
	cutoff        time.Time
	cutoffGuard   *identity.CutoffGuard
	cutoffExpired atomic.Bool
	instanceID    uint64
	peerData      identity.Verified
	now           func() time.Time
}

func (a *muxActivation) current(epoch uint64) bool {
	return a != nil && a.runner != nil && a.mux != nil && a.connection != nil && epoch == a.epoch &&
		a.runner.planAuthorityCurrent(a.lease, epoch)
}

func (a *muxActivation) PrepareDirect(epoch uint64) error {
	if a == nil || a.runner == nil || a.mux == nil || a.connection == nil || epoch != a.epoch {
		return datapath.ErrStalePath
	}
	return a.runner.withPlanAuthority(a.lease, epoch, func() error {
		if err := a.validateCutoffLocked(); err != nil {
			return err
		}
		priorDirectID := a.mux.Snapshot().DirectInstanceID
		instanceID, err := a.mux.PrepareDirectWithInstance(epoch, a.connection)
		if err == nil {
			a.instanceID = instanceID
			a.runner.bindPathIdentityLocked(
				a.mux, datapath.SelectedDirect, instanceID, a.peerData, priorDirectID,
			)
		}
		return err
	})
}

func (a *muxActivation) SelectDirect(epoch uint64) error {
	if a == nil || a.runner == nil || a.mux == nil || epoch != a.epoch {
		return datapath.ErrStalePath
	}
	err := a.runner.withPlanAuthority(a.lease, epoch, func() error {
		if err := a.validateCutoffLocked(); err != nil {
			return err
		}
		if _, ok := a.runner.pathPeerData[pathIdentityKey{
			mux: a.mux, path: datapath.SelectedDirect, instanceID: a.instanceID,
		}]; !ok {
			return datapath.ErrStalePath
		}
		err := a.mux.SelectDirect(epoch)
		if err == nil && a.runner.pathMux == a.mux {
			a.runner.refreshStatusTransitionsLocked()
		}
		return err
	})
	if err != nil {
		a.AbortDirect(epoch)
	}
	return err
}

func (a *muxActivation) CommitDirect(epoch uint64) error {
	if a == nil || a.runner == nil || a.mux == nil || epoch != a.epoch {
		return datapath.ErrStalePath
	}
	err := a.runner.withPlanAuthority(a.lease, epoch, func() error {
		if err := a.validateCutoffLocked(); err != nil {
			return err
		}
		key := pathIdentityKey{mux: a.mux, path: datapath.SelectedDirect, instanceID: a.instanceID}
		verified, ok := a.runner.pathPeerData[key]
		if !ok {
			return datapath.ErrStalePath
		}
		if err := a.mux.CommitDirect(epoch); err != nil {
			return err
		}
		a.runner.bindPathIdentityMapLocked(a.mux, datapath.SelectedDirect, a.instanceID, verified)
		if a.runner.pathMux == a.mux {
			a.runner.refreshStatusTransitionsLocked()
		}
		return nil
	})
	if err != nil {
		a.AbortDirect(epoch)
	}
	return err
}

func (a *muxActivation) AbortDirect(epoch uint64) {
	if a == nil || a.mux == nil {
		return
	}
	if a.runner == nil {
		a.mux.AbortDirect(epoch)
		return
	}
	a.runner.mu.Lock()
	a.mux.AbortDirect(epoch)
	a.runner.deletePathIdentityMapLocked(a.mux, datapath.SelectedDirect, a.instanceID)
	if a.runner.pathMux == a.mux {
		a.runner.refreshStatusTransitionsLocked()
	}
	a.runner.mu.Unlock()
}

// validateCutoffLocked runs only while Runner.mu serializes activation with
// plan revocation and cutoff expiry. The final CommitDirect invocation is the
// last wall-clock check before activation becomes irreversible.
func (a *muxActivation) validateCutoffLocked() error {
	if a == nil || a.cutoffGuard == nil || a.cutoff.IsZero() || a.cutoffExpired.Load() {
		return identity.ErrCertificateCutoff
	}
	now := time.Now
	if a.now != nil {
		now = a.now
	}
	observed := now()
	if observed.IsZero() || !observed.Before(a.cutoff) {
		return identity.ErrCertificateCutoff
	}
	return nil
}

// expireCutoff takes the same authority lock as every activation phase. Once
// it wins, no later mux mutation can pass validateCutoffLocked.
func (a *muxActivation) expireCutoff() {
	if a == nil {
		return
	}
	if a.runner != nil {
		a.runner.mu.Lock()
		a.cutoffExpired.Store(true)
		a.runner.mu.Unlock()
	} else {
		a.cutoffExpired.Store(true)
	}
	if a.connection != nil {
		_ = a.connection.Close("direct certificate rotation")
	}
}

type quicDataConnection struct {
	*quic.Conn
	closeOnce       sync.Once
	closeErr        error
	deliveryMu      sync.Mutex
	delivery        *direct.DeliveryMonitor
	deliveryBinding datapath.DeliveryBinding
	deliveryBindErr error
}

func (c *quicDataConnection) BindDelivery(binding datapath.DeliveryBinding) {
	if c == nil {
		return
	}
	c.deliveryMu.Lock()
	defer c.deliveryMu.Unlock()
	if c.delivery == nil || c.deliveryBinding.Acknowledge != nil || binding.Acknowledge == nil || binding.Fail == nil {
		c.deliveryBindErr = direct.ErrAuthentication
		return
	}
	c.deliveryBinding = binding
	c.deliveryBindErr = c.delivery.Bind(binding.Acknowledge, binding.Fail)
}

func (c *quicDataConnection) DatagramDelivered(sequence uint64) {
	if c == nil {
		return
	}
	c.deliveryMu.Lock()
	delivery := c.delivery
	c.deliveryMu.Unlock()
	if delivery != nil {
		delivery.DatagramDelivered(sequence)
	}
}

func (c *quicDataConnection) StartDelivery(ctx context.Context) error {
	if c == nil {
		return direct.ErrAuthentication
	}
	c.deliveryMu.Lock()
	delivery, err := c.delivery, c.deliveryBindErr
	bound := c.deliveryBinding.Acknowledge != nil && c.deliveryBinding.Fail != nil
	c.deliveryMu.Unlock()
	if err != nil || delivery == nil || !bound {
		return direct.ErrAuthentication
	}
	return delivery.Start(ctx)
}

func (c *quicDataConnection) FailDelivery() bool {
	if c == nil {
		return false
	}
	c.deliveryMu.Lock()
	fail := c.deliveryBinding.Fail
	c.deliveryMu.Unlock()
	return fail != nil && fail()
}

func (c *quicDataConnection) Close(reason string) error {
	if c == nil || c.Conn == nil {
		return nil
	}
	c.closeOnce.Do(func() { c.closeErr = c.CloseWithError(directCloseCode, reason) })
	return c.closeErr
}

func sameDirectAddress(address net.Addr, expected netip.AddrPort) bool {
	udpAddress, ok := address.(*net.UDPAddr)
	if !ok || udpAddress == nil || udpAddress.IP == nil || udpAddress.Port <= 0 || udpAddress.Port > 65535 {
		return false
	}
	actual, ok := netip.AddrFromSlice(udpAddress.IP)
	return ok && netip.AddrPortFrom(actual.Unmap(), uint16(udpAddress.Port)) == expected
}

func validateDatagramConnection(connection *quic.Conn, required int) error {
	if connection == nil || required <= datapath.WireOverhead || required > 65535 {
		return errors.New("invalid QUIC DATAGRAM capacity requirement")
	}
	state := connection.ConnectionState()
	if !state.SupportsDatagrams.Local || !state.SupportsDatagrams.Remote {
		return errors.New("peer did not negotiate QUIC DATAGRAM")
	}
	// An intentionally impossible payload queries quic-go's current effective
	// capacity without enqueuing an unauthenticated campus-link envelope.
	err := connection.SendDatagram(make([]byte, 65535))
	var tooLarge *quic.DatagramTooLargeError
	if err == nil || !errors.As(err, &tooLarge) || tooLarge.MaxDatagramPayloadSize < int64(required) {
		return errors.New("QUIC DATAGRAM capacity is below the configured inner MTU")
	}
	return nil
}
