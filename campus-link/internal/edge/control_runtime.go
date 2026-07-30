package edge

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/datapath"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/nonquic"
)

const (
	controlBindingWindow = 31 * time.Second
	controlRetryInitial  = 250 * time.Millisecond
	controlRetryMaximum  = 30 * time.Second
)

var errPlanAuthorityWithheld = errors.New("control plan authority withheld")

// authenticatedControlSession owns only broker authority. Its context is never
// an ancestor of the UDP transport, mux, TUN bridge, or an established direct
// QUIC connection.
type authenticatedControlSession struct {
	conn      *tls.Conn
	cancel    context.CancelFunc
	done      chan struct{}
	planLease planSessionLease
	closeOnce sync.Once
}

func (s *authenticatedControlSession) shutdown(r *Runner) {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		// Revoke under the same lock used by plan admission before interrupting
		// and joining the decoder. A racing final acknowledgement can therefore
		// never leave a plan actionable after this method returns.
		if r != nil && s.planLease.serial != 0 {
			r.endPlanSession(s.planLease)
		}
		if s.cancel != nil {
			s.cancel()
		}
		if s.conn != nil {
			_ = s.conn.Close()
		}
		if s.done != nil {
			<-s.done
		}
	})
}

func (r *Runner) connectControlWithRetry(
	ctx context.Context,
	controlTLS *tls.Config,
	localControl identity.Verified,
	dispatcher *nonquic.Dispatcher,
	relayUDP *net.UDPAddr,
) (*authenticatedControlSession, error) {
	attempt := uint(0)
	for {
		session, err := r.openControlSession(ctx, controlTLS, localControl, dispatcher, relayUDP)
		if err == nil {
			return session, nil
		}
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		r.setControlBindingState("reconnecting", "unbound")
		log.Printf("control session unavailable; bounded retry scheduled")
		delay := jitterRetryDelay(controlRetryDelay(attempt, controlRetryInitial, controlRetryMaximum), nil)
		if err := waitControlRetry(ctx, delay); err != nil {
			return nil, err
		}
		if attempt < ^uint(0) {
			attempt++
		}
	}
}

func waitControlRetry(ctx context.Context, delay time.Duration) error {
	if ctx == nil || delay <= 0 {
		return errors.New("invalid control retry wait")
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return nil
	}
}

func (r *Runner) superviseControl(
	ctx context.Context,
	controlTLS *tls.Config,
	localControl identity.Verified,
	dispatcher *nonquic.Dispatcher,
	relayUDP *net.UDPAddr,
	current *authenticatedControlSession,
) {
	for current != nil {
		select {
		case <-ctx.Done():
			current.shutdown(r)
			return
		case <-current.done:
		}

		// shutdown joins the old heartbeat before the next TLS connection can
		// authenticate, preventing a same-namespace ABA lease from revoking or
		// admitting plans on behalf of its successor.
		current.shutdown(r)
		r.setPeerControl(identity.Verified{})
		r.setControlBindingState("reconnecting", "unbound")
		if ctx.Err() != nil {
			return
		}
		next, err := r.connectControlWithRetry(ctx, controlTLS, localControl, dispatcher, relayUDP)
		if err != nil {
			return
		}
		current = next
	}
}

func (r *Runner) openControlSession(
	ctx context.Context,
	controlTLS *tls.Config,
	localControl identity.Verified,
	dispatcher *nonquic.Dispatcher,
	relayUDP *net.UDPAddr,
) (_ *authenticatedControlSession, resultErr error) {
	if ctx == nil || controlTLS == nil || dispatcher == nil || relayUDP == nil {
		return nil, errors.New("control session dependencies unavailable")
	}
	tlsDialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config:    controlTLS.Clone(),
	}
	dialCtx, cancelDial := context.WithTimeout(ctx, controlRegistrationWindow)
	raw, err := tlsDialer.DialContext(dialCtx, "tcp", r.cfg.RelayAddress)
	cancelDial()
	if err != nil {
		return nil, fmt.Errorf("control dial: %w", err)
	}
	controlConn, ok := raw.(*tls.Conn)
	if !ok {
		_ = raw.Close()
		return nil, errors.New("control dial did not return TLS")
	}
	var cancelSession context.CancelFunc
	defer func() {
		if resultErr == nil {
			return
		}
		if cancelSession != nil {
			cancelSession()
		}
		_ = controlConn.Close()
	}()

	peerControl, err := identity.VerifyConnection(controlConn.ConnectionState(), r.controlRequirements)
	if err != nil {
		return nil, fmt.Errorf("capture control peer identity: %w", err)
	}
	controlCutoff, err := identity.SessionDeadline(time.Now(), localControl, peerControl)
	if err != nil {
		return nil, fmt.Errorf("control certificate lifetime: %w", err)
	}
	sessionCtx, cancel := context.WithDeadline(ctx, controlCutoff)
	cancelSession = cancel
	if _, err := identity.GuardCertificateCutoff(sessionCtx, controlCutoff, func() {
		cancel()
		_ = controlConn.Close()
	}); err != nil {
		return nil, fmt.Errorf("control certificate cutoff guard: %w", err)
	}
	registrationDeadline, err := identity.BoundedDeadline(time.Now(), controlRegistrationWindow, controlCutoff)
	if err != nil {
		return nil, fmt.Errorf("control registration lifetime: %w", err)
	}
	if err := controlConn.SetDeadline(registrationDeadline); err != nil {
		return nil, fmt.Errorf("set control registration deadline: %w", err)
	}
	enc, dec := json.NewEncoder(controlConn), control.NewDecoder(controlConn)
	registration := control.Register{
		Type: "register", Site: r.cfg.Site, Generation: r.cfg.Generation, Version: r.version,
		DeploymentID: r.cfg.DeploymentID, Circuit: r.cfg.Circuit, Prefix: r.cfg.Prefix,
		Transports: []string{"quic-datagram"},
	}
	if err := enc.Encode(registration); err != nil {
		return nil, fmt.Errorf("control registration write: %w", err)
	}
	var registered control.Registered
	if err := dec.Decode(&registered); err != nil {
		return nil, fmt.Errorf("control registration response: %w", err)
	}
	if registered.Type != "registered" || !control.ValidSourceVersion(registered.Version) || registered.Version != r.version ||
		registered.DeploymentID != r.cfg.DeploymentID || !control.ValidRelayGeneration(registered.RelayGeneration) {
		return nil, errors.New("control registration rejected")
	}
	token, err := hex.DecodeString(registered.BindToken)
	if err != nil || len(token) != 32 {
		return nil, errors.New("invalid bind token")
	}

	r.setControlBindingState("authenticated", "unbound")
	bindingCtx, cancelBinding := context.WithTimeout(sessionCtx, controlBindingWindow)
	bindingLease, err := dispatcher.AcquireBinding(bindingCtx)
	if err != nil {
		cancelBinding()
		return nil, fmt.Errorf("binding mailbox: %w", err)
	}
	bindErr := bindNonQUICCount(bindingCtx, bindingLease, relayUDP, r.cfg.Site, token, &r.bindingRejected)
	bindingLease.Release()
	cancelBinding()
	if bindErr != nil {
		return nil, fmt.Errorf("authenticated UDP binding: %w", bindErr)
	}

	// Plan authority is deliberately the last capability enabled: exact TLS
	// peer/version/deployment/generation checks and authenticated UDP return
	// routability have all succeeded at this point.
	planLease := r.authorizePlanSession(registered.RelayGeneration, true)
	if planLease.serial == 0 {
		return nil, errPlanAuthorityWithheld
	}
	if err := controlConn.SetDeadline(controlCutoff); err != nil {
		r.endPlanSession(planLease)
		return nil, fmt.Errorf("set control certificate deadline: %w", err)
	}
	heartbeatErr := make(chan error, 1)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		if planLease.serial != 0 {
			defer r.endPlanSession(planLease)
		}
		r.heartbeatPlanSessionUntil(
			sessionCtx, cancelSession, controlConn, enc, dec, heartbeatErr, planLease, controlCutoff,
		)
	}()
	r.setPeerControl(peerControl)
	r.setControlBindingState("authenticated", "bound")
	return &authenticatedControlSession{
		conn: controlConn, cancel: cancelSession, done: heartbeatDone, planLease: planLease,
	}, nil
}

// authorizePlanSession handles a deliberate authority namespace change before
// beginPlanSession can reset the epoch. An old direct path is explicitly
// retired onto a healthy relay; otherwise admission remains fail-closed.
func (r *Runner) authorizePlanSession(relayGeneration string, bindingValidated bool) planSessionLease {
	if !bindingValidated {
		return planSessionLease{}
	}
	namespace, err := planAuthorityNamespace(r.version, r.cfg.DeploymentID, relayGeneration)
	if err != nil {
		return planSessionLease{}
	}
	mux, changed := r.quarantineChangedPlanNamespace(namespace)
	if changed && mux != nil {
		snapshot := mux.Snapshot()
		hadHealthyDirect := snapshot.DirectHealthy
		if hadHealthyDirect && !snapshot.RelayHealthy {
			return planSessionLease{}
		}
		if !mux.RetireDirect() {
			return planSessionLease{}
		}
		snapshot = mux.Snapshot()
		if snapshot.DirectHealthy || (hadHealthyDirect && !snapshot.RelayHealthy) {
			return planSessionLease{}
		}
		if hadHealthyDirect {
			r.setDirectAttempt("retired")
		}
	}
	if changed {
		r.clearPlanNamespaceBlock(namespace)
	}
	return r.beginPlanSession(relayGeneration)
}

func (r *Runner) quarantineChangedPlanNamespace(namespace string) (*datapath.Mux, bool) {
	r.mu.Lock()
	if r.planNamespace == "" {
		r.mu.Unlock()
		return r.pathMux, false
	}
	if r.planNamespace == namespace {
		mux, blocked := r.pathMux, r.blockedPlanNamespace == namespace
		r.mu.Unlock()
		return mux, blocked
	}
	r.drainPlansLocked()
	cancelAuthority := r.planSessionCancel
	r.planNamespace = namespace
	r.blockedPlanNamespace = namespace
	r.relayGeneration = ""
	r.activePlanSession = 0
	r.planSessionAuthority = nil
	r.planSessionCancel = nil
	r.state.RelayTelemetry = nil
	r.rememberedPlan = nil
	r.resetClockAuthorityLocked()
	r.planEpoch.Store(0)
	mux := r.pathMux
	r.mu.Unlock()
	if cancelAuthority != nil {
		cancelAuthority()
	}
	r.writeStatus()
	return mux, true
}

func (r *Runner) clearPlanNamespaceBlock(namespace string) {
	r.mu.Lock()
	if r.planNamespace == namespace {
		r.blockedPlanNamespace = ""
	}
	r.mu.Unlock()
}

func (r *Runner) setControlBindingState(controlState, udpState string) {
	r.mu.Lock()
	r.state.Control, r.state.UDP = controlState, udpState
	r.mu.Unlock()
	r.writeStatus()
}

func (r *Runner) setDataState(quicState, tunState string) {
	r.mu.Lock()
	r.state.QUIC, r.state.TUN = quicState, tunState
	r.mu.Unlock()
	r.writeStatus()
}
