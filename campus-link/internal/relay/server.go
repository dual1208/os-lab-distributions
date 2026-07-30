package relay

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/binding"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/rendezvous"
)

type leg struct {
	owner       uint64
	control     net.Conn
	token       []byte
	generation  string
	online      bool
	bound       bool
	addr        *net.UDPAddr
	pendingAddr *net.UDPAddr
	bindState   *binding.ServerState
	readyPacket []byte
	verified    identity.Verified
	cutoff      time.Time
}

type Server struct {
	cfg                 config.Relay
	version             string
	relayGeneration     string
	mu                  sync.Mutex
	udpMu               sync.Mutex
	admissionMu         sync.Mutex
	legs                map[string]*leg
	forwardA            uint64
	forwardABytes       uint64
	forwardB            uint64
	forwardBBytes       uint64
	dropped             uint64
	droppedBytes        uint64
	rejectedControl     uint64
	nextOwner           uint64
	established         bool
	udp                 *net.UDPConn
	planner             *rendezvous.Planner
	controlRequirements map[string]identity.Requirements
	controlSlots        chan struct{}
	preauthBySource     map[string]int
	statusQueue         chan status
	statusWriteFailures atomic.Uint64
	localControl        identity.Verified
}

const (
	maxOuterDatagramSize   = 2048
	maxUDPDatagramSize     = 65535
	maxPreauthConnections  = 8
	maxPreauthPerSource    = 2
	controlAdmissionWindow = 10 * time.Second
	minHeartbeatInterval   = time.Second
	udpWriteDeadline       = 250 * time.Millisecond
)

type status struct {
	Circuit         string                `json:"circuit"`
	LocalIdentity   *certificateStatus    `json:"local_control_identity,omitempty"`
	Sites           map[string]siteStatus `json:"sites"`
	Forward         map[string]uint64     `json:"forwarded_packets"`
	ForwardBytes    map[string]uint64     `json:"forwarded_bytes"`
	Dropped         uint64                `json:"dropped_packets"`
	DroppedBytes    uint64                `json:"dropped_bytes"`
	RejectedControl uint64                `json:"rejected_control_connections"`
	StatusFailures  uint64                `json:"status_write_failures"`
	Updated         time.Time             `json:"updated"`
}

var errRelayTelemetryOverflow = errors.New("relay telemetry counter overflow")

type siteStatus struct {
	Control         string             `json:"control"`
	UDP             string             `json:"udp"`
	ControlIdentity *certificateStatus `json:"control_identity,omitempty"`
}

type certificateStatus struct {
	Expires string `json:"expires"`
	PinSlot string `json:"pin_slot"`
}

func New(cfg config.Relay, version string) (*Server, error) {
	return newServer(cfg, version, true, nil)
}

// NewForPreflight validates static authority without creating or reserving
// runtime epoch state. It must never be used to start listeners.
func NewForPreflight(cfg config.Relay, version string) (*Server, error) {
	return newServer(cfg, version, false, nil)
}

func newServer(cfg config.Relay, version string, initializeEpochState bool, bootAnchorSource rendezvous.BootAnchorSource) (*Server, error) {
	if cfg.Circuit == "" || len(cfg.Prefixes) != 2 ||
		cfg.Prefixes["site-a"] != config.CampusSiteAPrefix || cfg.Prefixes["site-b"] != config.CampusSiteBPrefix {
		return nil, errors.New("relay requires one circuit and fixed site-a/site-b prefixes")
	}
	if !control.ValidSourceVersion(version) || !control.ValidDeploymentID(cfg.DeploymentID) || !filepath.IsAbs(cfg.EpochStatePath) {
		return nil, errors.New("relay requires source version, canonical deployment ID, and epoch state path")
	}
	if len(cfg.ControlIdentities) != 2 {
		return nil, errors.New("relay requires exactly two control identity authorizations")
	}
	controlRequirements := make(map[string]identity.Requirements, 2)
	seenPins := make(map[string]string, 4)
	for _, site := range []string{"site-a", "site-b"} {
		authorization, ok := cfg.ControlIdentities[site]
		if !ok {
			return nil, errors.New("relay requires site-a and site-b control identity authorizations")
		}
		expectedURI, err := expectedIdentityURI(cfg.Circuit, site, "control")
		if err != nil {
			return nil, err
		}
		requirements, err := authorizationRequirements(authorization, expectedURI, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		if err != nil {
			return nil, fmt.Errorf("invalid %s control identity authorization: %w", site, err)
		}
		for _, pin := range requirements.Pins {
			if previousSite, duplicate := seenPins[pin]; duplicate {
				return nil, fmt.Errorf("control SPKI pin is reused by %s and %s", previousSite, site)
			}
			seenPins[pin] = site
		}
		controlRequirements[site] = requirements
	}
	var planner *rendezvous.Planner
	var relayGeneration string
	if initializeEpochState {
		var epochStore *rendezvous.FileEpochStore
		var err error
		if bootAnchorSource == nil {
			epochStore, err = rendezvous.OpenFileEpochStore(cfg.EpochStatePath, cfg.DeploymentID, nil)
		} else {
			epochStore, err = rendezvous.OpenFileEpochStoreWithAnchor(
				cfg.EpochStatePath, cfg.DeploymentID, nil, bootAnchorSource,
			)
		}
		if err != nil {
			return nil, fmt.Errorf("rendezvous epoch state: %w", err)
		}
		planner, err = rendezvous.NewPlanner(cfg.Circuit, version, epochStore)
		if err != nil {
			return nil, fmt.Errorf("rendezvous planner: %w", err)
		}
		relayGeneration = epochStore.Namespace().RelayGeneration
	}
	return &Server{
		cfg: cfg, version: version, relayGeneration: relayGeneration,
		legs:    map[string]*leg{"site-a": {}, "site-b": {}},
		planner: planner, controlRequirements: controlRequirements,
		controlSlots:    make(chan struct{}, maxPreauthConnections),
		preauthBySource: make(map[string]int), statusQueue: make(chan status, 1),
	}, nil
}

func authorizationRequirements(authorization config.IdentityAuthorization, expectedURI string, usages []x509.ExtKeyUsage) (identity.Requirements, error) {
	if authorization.URI != expectedURI {
		return identity.Requirements{}, identity.ErrPeerIdentity
	}
	pins := []string{authorization.CurrentSPKI}
	if authorization.NextSPKI != "" {
		pins = append(pins, authorization.NextSPKI)
	}
	requirements := identity.Requirements{URI: authorization.URI, Pins: pins, Usages: usages}
	if err := identity.ValidateRequirements(requirements); err != nil {
		return identity.Requirements{}, err
	}
	return requirements, nil
}

func expectedIdentityURI(circuit, endpoint, plane string) (string, error) {
	if !safeIdentitySegment(circuit) || !safeIdentitySegment(endpoint) || !safeIdentitySegment(plane) {
		return "", errors.New("identity URI components must be canonical path segments")
	}
	return fmt.Sprintf("spiffe://campus-link/%s/%s/%s", circuit, endpoint, plane), nil
}

func safeIdentitySegment(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, c := range []byte(value) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			continue
		}
		return false
	}
	return true
}

func (s *Server) Run(ctx context.Context) error {
	if s.planner == nil || !control.ValidRelayGeneration(s.relayGeneration) {
		return errors.New("relay runtime epoch authority is unavailable")
	}
	material, err := s.validatedTLSMaterial(time.Now())
	if err != nil {
		return fmt.Errorf("configuration preflight: %w", err)
	}
	localCutoff, err := identity.SessionDeadline(time.Now(), material.localControl)
	if err != nil {
		return fmt.Errorf("local relay certificate lifetime: %w", err)
	}
	deadlineCtx, cancelDeadline := context.WithDeadline(ctx, localCutoff)
	defer cancelDeadline()
	runCtx, cancelRunCause := context.WithCancelCause(deadlineCtx)
	cancelRun := func() { cancelRunCause(context.Canceled) }
	defer cancelRun()
	cutoffGuard, err := identity.GuardCertificateCutoff(runCtx, localCutoff, func() {
		cancelRunCause(identity.ErrCertificateCutoff)
	})
	if err != nil {
		return fmt.Errorf("local relay certificate cutoff guard: %w", err)
	}
	defer cutoffGuard.Stop()
	tlsConfig := material.config
	s.mu.Lock()
	s.localControl = material.localControl
	s.mu.Unlock()
	tcp, err := tls.Listen("tcp", s.cfg.ControlListen, tlsConfig)
	if err != nil {
		return fmt.Errorf("control listen: %w", err)
	}
	defer tcp.Close()
	udpAddr, err := net.ResolveUDPAddr("udp", s.cfg.UDPListen)
	if err != nil {
		return err
	}
	s.udp, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("UDP listen: %w", err)
	}
	defer s.udp.Close()

	errCh := make(chan error, 2)
	go func() { errCh <- s.acceptControl(runCtx, tcp) }()
	go func() { errCh <- s.spliceUDP(runCtx) }()
	go s.writeStatusLoop(runCtx)
	go s.statusWriter(runCtx)
	s.mu.Lock()
	s.queueStatusLocked()
	s.mu.Unlock()
	log.Printf("campus-link relay ready: circuit=%s", s.cfg.Circuit)
	select {
	case <-runCtx.Done():
		if ctx.Err() != nil {
			return nil
		}
		cause := context.Cause(runCtx)
		if errors.Is(cause, context.DeadlineExceeded) || errors.Is(cause, identity.ErrCertificateCutoff) {
			return errors.New("local relay certificate rotation deadline reached")
		}
		return cause
	case err := <-errCh:
		return err
	}
}

func (s *Server) acceptControl(ctx context.Context, listener net.Listener) error {
	var retryDelay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if networkError, ok := err.(net.Error); ok && networkError.Temporary() {
				if retryDelay == 0 {
					retryDelay = 5 * time.Millisecond
				} else {
					retryDelay *= 2
				}
				if retryDelay > time.Second {
					retryDelay = time.Second
				}
				timer := time.NewTimer(retryDelay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil
				case <-timer.C:
				}
				continue
			}
			return err
		}
		retryDelay = 0
		remoteAddress := conn.RemoteAddr()
		if !s.acquireControlSlot(remoteAddress) {
			_ = conn.Close()
			s.mu.Lock()
			s.rejectedControl++
			s.queueStatusLocked()
			s.mu.Unlock()
			continue
		}
		go s.handleControlWithAdmission(conn, func() { s.releaseControlSlot(remoteAddress) })
	}
}

func admissionSource(address net.Addr) (string, bool) {
	if address == nil {
		return "", false
	}
	if tcpAddress, ok := address.(*net.TCPAddr); ok {
		if tcpAddress.IP == nil {
			return "", false
		}
		return tcpAddress.IP.String(), true
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil || host == "" {
		return "", false
	}
	return host, true
}

func (s *Server) acquireControlSlot(address net.Addr) bool {
	source, ok := admissionSource(address)
	if !ok {
		return false
	}
	s.admissionMu.Lock()
	defer s.admissionMu.Unlock()
	if s.preauthBySource[source] >= maxPreauthPerSource {
		return false
	}
	select {
	case s.controlSlots <- struct{}{}:
		s.preauthBySource[source]++
		return true
	default:
		return false
	}
}

func (s *Server) releaseControlSlot(address net.Addr) {
	source, ok := admissionSource(address)
	if !ok {
		return
	}
	s.admissionMu.Lock()
	defer s.admissionMu.Unlock()
	if s.preauthBySource[source] <= 0 {
		return
	}
	s.preauthBySource[source]--
	if s.preauthBySource[source] == 0 {
		delete(s.preauthBySource, source)
	}
	<-s.controlSlots
}

func (s *Server) handleControl(raw net.Conn) {
	s.handleControlWithAdmission(raw, nil)
}

func (s *Server) handleControlWithAdmission(raw net.Conn, releasePreauth func()) {
	var releaseOnce sync.Once
	release := func() {
		if releasePreauth != nil {
			releaseOnce.Do(releasePreauth)
		}
	}
	defer release()
	defer raw.Close()
	conn, ok := raw.(*tls.Conn)
	if !ok {
		return
	}
	localControl := s.localControlIdentity()
	localCutoff, err := identity.SessionDeadline(time.Now(), localControl)
	if err != nil {
		return
	}
	admissionDeadline, err := identity.BoundedDeadline(time.Now(), controlAdmissionWindow, localCutoff)
	if err != nil || conn.SetDeadline(admissionDeadline) != nil {
		return
	}
	if err := conn.Handshake(); err != nil {
		return
	}
	state := conn.ConnectionState()
	identityName, peerVerified, err := s.authorizedSiteVerified(state)
	if err != nil {
		return
	}
	cutoff, err := identity.SessionDeadline(time.Now(), localControl, peerVerified)
	if err != nil {
		return
	}
	if cutoff.Before(admissionDeadline) {
		admissionDeadline = cutoff
	}
	if err := conn.SetDeadline(admissionDeadline); err != nil {
		return
	}
	expiryGuard, err := closeConnectionAtCutoff(conn, cutoff)
	if err != nil {
		return
	}
	defer expiryGuard.Stop()
	dec := control.NewDecoder(conn)
	enc := json.NewEncoder(conn)
	var reg control.Register
	if err := dec.Decode(&reg); err != nil {
		return
	}
	if !s.validRegistration(reg, identityName) {
		_ = enc.Encode(control.Error{Type: "error", Message: "registration rejected"})
		return
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return
	}
	prepared, err := prepareLeg(identityName, reg.Generation, token, conn)
	if err != nil {
		return
	}
	prepared.verified, prepared.cutoff = peerVerified, cutoff
	// Deliver the new binding capability before changing authority. A failed
	// Registered write must leave an established pair untouched.
	if err := enc.Encode(s.registeredResponse(token)); err != nil {
		return
	}
	s.udpMu.Lock()
	s.mu.Lock()
	owner, err := s.activatePreparedLegLocked(identityName, prepared)
	if err == nil {
		s.queueStatusLocked()
	}
	s.mu.Unlock()
	s.udpMu.Unlock()
	if err != nil {
		return
	}
	release()
	defer func() {
		s.udpMu.Lock()
		s.mu.Lock()
		cleared := s.clearLegLocked(identityName, owner)
		if cleared {
			s.queueStatusLocked()
		}
		s.mu.Unlock()
		s.udpMu.Unlock()
		if cleared {
			log.Printf("control disconnected: site=%s", identityName)
		}
	}()
	log.Printf("control authenticated: site=%s", identityName)
	if err := conn.SetDeadline(cutoff); err != nil {
		return
	}
	var lastSequence uint64
	var lastHeartbeat time.Time
	for {
		readDeadline, err := relayControlDeadline(time.Now(), 45*time.Second, cutoff)
		if err != nil || conn.SetReadDeadline(readDeadline) != nil {
			break
		}
		var hb control.Heartbeat
		if err := dec.Decode(&hb); err != nil {
			break
		}
		now := time.Now()
		if !validHeartbeat(hb, lastSequence, lastHeartbeat, now) {
			break
		}
		lastSequence = hb.Sequence
		lastHeartbeat = now
		writeDeadline, err := relayControlDeadline(time.Now(), 5*time.Second, cutoff)
		if err != nil || conn.SetWriteDeadline(writeDeadline) != nil {
			break
		}
		var plan *control.RendezvousPlan
		s.mu.Lock()
		candidate, planOK := s.planner.PlanFor(identityName, owner)
		planOK = planOK && legAuthorizedAt(s.legs[identityName], time.Now()) && s.legs[identityName].owner == owner
		telemetry := s.relayTelemetryLocked()
		s.mu.Unlock()
		if planOK {
			plan = &candidate
		}
		relaySend := time.Now()
		ack, ok := relayClockAcknowledgement(hb, now, relaySend)
		if !ok {
			break
		}
		ack.Telemetry, ack.Plan = &telemetry, plan
		if err := enc.Encode(ack); err != nil {
			break
		}
	}
}

func (s *Server) validRegistration(reg control.Register, authenticatedSite string) bool {
	return reg.Type == "register" && reg.Site == authenticatedSite && reg.Circuit == s.cfg.Circuit &&
		reg.Prefix == s.cfg.Prefixes[authenticatedSite] && reg.Generation != "" &&
		control.ValidSourceVersion(reg.Version) && reg.Version == s.version && reg.DeploymentID == s.cfg.DeploymentID &&
		len(reg.Transports) == 1 && reg.Transports[0] == "quic-datagram"
}

// relayTelemetryLocked returns one coherent fixed-width snapshot. Callers must
// hold s.mu, which is also the authority lock for all six counters.
func (s *Server) relayTelemetryLocked() control.RelayTelemetry {
	return control.RelayTelemetry{
		ForwardedSiteA:      s.forwardA,
		ForwardedSiteABytes: s.forwardABytes,
		ForwardedSiteB:      s.forwardB,
		ForwardedSiteBBytes: s.forwardBBytes,
		Dropped:             s.dropped,
		DroppedBytes:        s.droppedBytes,
	}
}

func relayCounterCanAdd(packets, bytes, payloadBytes uint64) bool {
	return packets != ^uint64(0) && bytes <= ^uint64(0)-payloadBytes
}

func (s *Server) canRecordForwardedLocked(site string, payloadBytes uint64) bool {
	switch site {
	case "site-a":
		return relayCounterCanAdd(s.forwardA, s.forwardABytes, payloadBytes)
	case "site-b":
		return relayCounterCanAdd(s.forwardB, s.forwardBBytes, payloadBytes)
	default:
		return false
	}
}

func (s *Server) recordForwardedLocked(site string, payloadBytes uint64) error {
	if !s.canRecordForwardedLocked(site, payloadBytes) {
		return errRelayTelemetryOverflow
	}
	switch site {
	case "site-a":
		s.forwardA++
		s.forwardABytes += payloadBytes
	case "site-b":
		s.forwardB++
		s.forwardBBytes += payloadBytes
	}
	return nil
}

func (s *Server) canRecordDroppedLocked(payloadBytes uint64) bool {
	return relayCounterCanAdd(s.dropped, s.droppedBytes, payloadBytes)
}

func (s *Server) recordDroppedLocked(payloadBytes uint64) error {
	if !s.canRecordDroppedLocked(payloadBytes) {
		return errRelayTelemetryOverflow
	}
	s.dropped++
	s.droppedBytes += payloadBytes
	return nil
}

func (s *Server) registeredResponse(token []byte) control.Registered {
	return control.Registered{
		Type: "registered", BindToken: hex.EncodeToString(token), Version: s.version,
		DeploymentID: s.cfg.DeploymentID, RelayGeneration: s.relayGeneration,
	}
}

func relayControlDeadline(now time.Time, timeout time.Duration, cutoff time.Time) (time.Time, error) {
	return identity.BoundedDeadline(now, timeout, cutoff)
}

func closeConnectionAtCutoff(conn net.Conn, cutoff time.Time) (*identity.CutoffGuard, error) {
	if conn == nil {
		return nil, identity.ErrPeerIdentity
	}
	return identity.GuardCertificateCutoff(context.Background(), cutoff, func() { _ = conn.Close() })
}

func validHeartbeat(hb control.Heartbeat, lastSequence uint64, lastHeartbeat, now time.Time) bool {
	if hb.Type != "heartbeat" || hb.Sequence == 0 || hb.Sequence <= lastSequence || now.IsZero() ||
		!control.ValidClockUnixNano(now.UnixNano()) || !control.ValidClockUnixNano(hb.EdgeWallUnixNano) ||
		!control.ValidMonotonicSample(hb.EdgeMonotonicNano) {
		return false
	}
	return lastHeartbeat.IsZero() || now.Sub(lastHeartbeat) >= minHeartbeatInterval
}

func relayClockAcknowledgement(hb control.Heartbeat, receivedAt, sentAt time.Time) (control.HeartbeatAck, bool) {
	return relayClockAcknowledgementCaptured(hb, receivedAt, sentAt, receivedAt.UnixNano(), sentAt.UnixNano())
}

func relayClockAcknowledgementCaptured(
	hb control.Heartbeat,
	receivedAt, sentAt time.Time,
	receivedWallUnixNano, sentWallUnixNano int64,
) (control.HeartbeatAck, bool) {
	if hb.Type != "heartbeat" || hb.Sequence == 0 || !control.ValidMonotonicSample(hb.EdgeMonotonicNano) ||
		receivedAt.IsZero() || sentAt.IsZero() || !control.ValidClockUnixNano(receivedWallUnixNano) ||
		!control.ValidClockUnixNano(sentWallUnixNano) {
		return control.HeartbeatAck{}, false
	}
	monotonicProcessing := sentAt.Sub(receivedAt)
	wallProcessing := sentWallUnixNano - receivedWallUnixNano
	if monotonicProcessing < 0 || monotonicProcessing > time.Second || wallProcessing < 0 ||
		wallProcessing-monotonicProcessing.Nanoseconds() > int64(50*time.Millisecond) ||
		monotonicProcessing.Nanoseconds()-wallProcessing > int64(50*time.Millisecond) {
		return control.HeartbeatAck{}, false
	}
	return control.HeartbeatAck{
		Type: "heartbeat-ack", Sequence: hb.Sequence, EdgeMonotonicNano: hb.EdgeMonotonicNano,
		RelayReceiveUnixNano: receivedWallUnixNano, RelaySendUnixNano: sentWallUnixNano,
	}, true
}

func (s *Server) spliceUDP(ctx context.Context) error {
	// Read the complete protocol-sized UDP payload before enforcing the much
	// smaller campus-link envelope bound so dropped-byte accounting is exact.
	buf := make([]byte, maxUDPDatagramSize)
	for {
		if err := s.udp.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		n, src, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return nil
				}
				continue
			}
			return err
		}
		packet := append([]byte(nil), buf[:n]...)
		if n > maxOuterDatagramSize {
			s.mu.Lock()
			accountingErr := s.recordDroppedLocked(uint64(n))
			s.mu.Unlock()
			if accountingErr != nil {
				return accountingErr
			}
			continue
		}
		consumed, err := s.handleBinding(packet, src)
		if err != nil {
			return err
		}
		if consumed {
			continue
		}
		s.udpMu.Lock()
		s.mu.Lock()
		var dst *net.UDPAddr
		forwardSite := ""
		forwardCutoff := time.Time{}
		var accountingErr error
		now := time.Now()
		circuitAuthorized := legAuthorizedAt(s.legs["site-a"], now) && legAuthorizedAt(s.legs["site-b"], now)
		switch {
		case circuitAuthorized && sameAddr(src, s.legs["site-a"].addr) && s.legs["site-a"].bound && s.legs["site-b"].bound:
			dst = cloneAddr(s.legs["site-b"].addr)
			forwardSite = "site-a"
			forwardCutoff = earliestCutoff(s.legs["site-a"].cutoff, s.legs["site-b"].cutoff)
		case circuitAuthorized && sameAddr(src, s.legs["site-b"].addr) && s.legs["site-a"].bound && s.legs["site-b"].bound:
			dst = cloneAddr(s.legs["site-a"].addr)
			forwardSite = "site-b"
			forwardCutoff = earliestCutoff(s.legs["site-a"].cutoff, s.legs["site-b"].cutoff)
		default:
			accountingErr = s.recordDroppedLocked(uint64(n))
		}
		if dst != nil && (!s.canRecordForwardedLocked(forwardSite, uint64(n)) || !s.canRecordDroppedLocked(uint64(n))) {
			accountingErr = errRelayTelemetryOverflow
		}
		s.mu.Unlock()
		if accountingErr != nil {
			s.udpMu.Unlock()
			return accountingErr
		}
		if dst != nil {
			writeErr := s.writeUDPBefore(packet, dst, forwardCutoff)
			s.mu.Lock()
			if writeErr == nil {
				accountingErr = s.recordForwardedLocked(forwardSite, uint64(n))
			} else {
				accountingErr = s.recordDroppedLocked(uint64(n))
			}
			s.mu.Unlock()
		}
		s.udpMu.Unlock()
		if accountingErr != nil {
			return accountingErr
		}
	}
}

// writeUDP is called only while udpMu is held. That dedicated authority lock
// keeps revocation linearizable without blocking status/control work on s.mu.
func (s *Server) writeUDP(packet []byte, dst *net.UDPAddr) error {
	return s.writeUDPBefore(packet, dst, time.Time{})
}

func (s *Server) writeUDPBefore(packet []byte, dst *net.UDPAddr, cutoff time.Time) error {
	deadline := time.Now().Add(udpWriteDeadline)
	if !cutoff.IsZero() {
		var err error
		deadline, err = identity.BoundedDeadline(time.Now(), udpWriteDeadline, cutoff)
		if err != nil {
			return err
		}
	}
	if err := s.udp.SetWriteDeadline(deadline); err != nil {
		return err
	}
	written, err := s.udp.WriteToUDP(packet, dst)
	clearErr := s.udp.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}
	if written != len(packet) {
		return io.ErrShortWrite
	}
	return clearErr
}

func (s *Server) activateLegLocked(site, generation string, token []byte, conn net.Conn) (uint64, error) {
	prepared, err := prepareLeg(site, generation, token, conn)
	if err != nil {
		return 0, err
	}
	return s.activatePreparedLegLocked(site, prepared)
}

func prepareLeg(site, generation string, token []byte, conn net.Conn) (leg, error) {
	if generation == "" || conn == nil {
		return leg{}, errors.New("prepared control leg requires generation and connection")
	}
	bindState, err := binding.NewServerState(site, token)
	if err != nil {
		return leg{}, err
	}
	return leg{
		control: conn, token: append([]byte(nil), token...), generation: generation,
		online: true, bindState: bindState,
	}, nil
}

func (s *Server) activatePreparedLegLocked(site string, prepared leg) (uint64, error) {
	if prepared.control == nil || prepared.generation == "" || !prepared.online ||
		prepared.bindState == nil || len(prepared.token) != binding.TokenSize ||
		(!prepared.cutoff.IsZero() && !prepared.cutoff.After(time.Now())) {
		return 0, errors.New("invalid prepared control leg")
	}
	nextOwner := s.nextOwner + 1
	if err := s.planner.Register(site, prepared.generation, nextOwner); err != nil {
		return 0, err
	}
	if s.legs[site].online {
		_ = s.legs[site].control.Close()
		*s.legs[site] = leg{}
	}
	if s.established {
		peer := otherSite(site)
		if s.legs[peer].online {
			s.planner.Invalidate(peer, s.legs[peer].owner)
			_ = s.legs[peer].control.Close()
			*s.legs[peer] = leg{}
		}
		s.established = false
	}
	s.nextOwner = nextOwner
	prepared.owner = nextOwner
	*s.legs[site] = prepared
	if legAuthorizedAt(s.legs["site-a"], time.Now()) && legAuthorizedAt(s.legs["site-b"], time.Now()) {
		s.established = true
	}
	return nextOwner, nil
}

func (s *Server) clearLegLocked(site string, owner uint64) bool {
	l := s.legs[site]
	if l.owner != owner {
		return false
	}
	*l = leg{}
	s.planner.Invalidate(site, owner)
	if s.established {
		peer := otherSite(site)
		if s.legs[peer].online {
			s.planner.Invalidate(peer, s.legs[peer].owner)
			_ = s.legs[peer].control.Close()
			*s.legs[peer] = leg{}
		}
		s.established = false
	}
	return true
}

func otherSite(site string) string {
	if site == "site-a" {
		return "site-b"
	}
	return "site-a"
}

func legAuthorizedAt(l *leg, now time.Time) bool {
	return l != nil && l.online && !now.IsZero() && (l.cutoff.IsZero() || now.Before(l.cutoff))
}

func earliestCutoff(first, second time.Time) time.Time {
	if first.IsZero() {
		return second
	}
	if second.IsZero() || first.Before(second) {
		return first
	}
	return second
}

type udpReply struct {
	packet []byte
	dst    *net.UDPAddr
}

func (s *Server) handleBinding(packet []byte, src *net.UDPAddr) (bool, error) {
	s.udpMu.Lock()
	s.mu.Lock()
	consumed, replies, rejected := s.handleBindingLocked(packet, src)
	if rejected {
		if err := s.recordDroppedLocked(uint64(len(packet))); err != nil {
			s.mu.Unlock()
			s.udpMu.Unlock()
			return consumed, err
		}
	}
	s.mu.Unlock()
	for _, reply := range replies {
		s.mu.Lock()
		canRecordFailure := s.canRecordDroppedLocked(uint64(len(reply.packet)))
		s.mu.Unlock()
		if !canRecordFailure {
			s.udpMu.Unlock()
			return consumed, errRelayTelemetryOverflow
		}
		if err := s.writeUDP(reply.packet, reply.dst); err != nil {
			s.mu.Lock()
			accountingErr := s.recordDroppedLocked(uint64(len(reply.packet)))
			s.mu.Unlock()
			if accountingErr != nil {
				s.udpMu.Unlock()
				return consumed, accountingErr
			}
		}
	}
	s.udpMu.Unlock()
	return consumed, nil
}

// handleBindingLocked mutates authority under s.mu while the caller holds
// udpMu. It returns immutable replies so socket I/O occurs without s.mu.
func (s *Server) handleBindingLocked(packet []byte, src *net.UDPAddr) (bool, []udpReply, bool) {
	var replies []udpReply
	now := time.Now()
	circuitAuthorized := legAuthorizedAt(s.legs["site-a"], now) && legAuthorizedAt(s.legs["site-b"], now)
	for site, l := range s.legs {
		if !legAuthorizedAt(l, now) || len(l.token) == 0 || l.bindState == nil {
			continue
		}
		if request, ok := binding.ParseRequest(packet, l.token); ok {
			snapshot := l.bindState.Snapshot()
			if snapshot.Active && request.Sequence == snapshot.Sequence && request.RequestNonce == snapshot.RequestNonce {
				expected := l.pendingAddr
				if snapshot.Complete {
					expected = l.addr
				}
				if !sameAddr(src, expected) {
					return true, replies, true
				}
			}
			result, err := l.bindState.Handle(packet)
			if err != nil {
				return true, replies, true
			}
			switch result.Action {
			case binding.ActionSendChallenge:
				if !snapshot.Active || result.Metadata.Sequence != snapshot.Sequence || result.Metadata.RequestNonce != snapshot.RequestNonce {
					// Keep a previously proven tuple active until the new source
					// proves return routability. The matching response atomically
					// replaces it; pending sources are never allowed to forward.
					l.pendingAddr = cloneAddr(src)
					l.readyPacket = nil
				}
				replies = append(replies, udpReply{packet: append([]byte(nil), result.Reply...), dst: cloneAddr(src)})
			case binding.ActionSendReady:
				if circuitAuthorized && s.legs["site-a"].bound && s.legs["site-b"].bound {
					replies = append(replies, udpReply{packet: append([]byte(nil), result.Reply...), dst: cloneAddr(src)})
				}
			default:
				return true, replies, true
			}
			return true, replies, false
		}
		if response, ok := binding.ParseResponse(packet, l.token); ok {
			snapshot := l.bindState.Snapshot()
			expected := l.pendingAddr
			if snapshot.Complete {
				expected = l.addr
			}
			if !snapshot.Active || response.Site != site || response.Sequence != snapshot.Sequence ||
				response.RequestNonce != snapshot.RequestNonce || response.Challenge != snapshot.Challenge ||
				!sameAddr(src, expected) {
				return true, replies, true
			}
			result, err := l.bindState.Handle(packet)
			if err != nil || result.Action != binding.ActionSendReady {
				return true, replies, true
			}
			if result.NewlyCompleted {
				l.addr = cloneAddr(src)
				l.bound = true
				l.pendingAddr = nil
				l.readyPacket = append([]byte(nil), result.Reply...)
				if ip, ok := netip.AddrFromSlice(src.IP); ok {
					if err := s.planner.Observe(site, l.owner, netip.AddrPortFrom(ip.Unmap(), uint16(src.Port)), time.Now()); err != nil {
						s.planner.Withdraw(site, l.owner)
					}
				} else {
					s.planner.Withdraw(site, l.owner)
				}
				log.Printf("UDP tuple authenticated: site=%s", site)
				s.queueStatusLocked()
				if circuitAuthorized && s.legs["site-a"].bound && s.legs["site-b"].bound {
					for _, readySite := range []string{"site-a", "site-b"} {
						readyLeg := s.legs[readySite]
						if len(readyLeg.readyPacket) != 0 {
							replies = append(replies, udpReply{
								packet: append([]byte(nil), readyLeg.readyPacket...), dst: cloneAddr(readyLeg.addr),
							})
						}
					}
				}
			} else if circuitAuthorized && s.legs["site-a"].bound && s.legs["site-b"].bound {
				// A lost READY is recovered by replaying the authenticated
				// response from the tuple that originally completed it.
				replies = append(replies, udpReply{packet: append([]byte(nil), result.Reply...), dst: cloneAddr(src)})
			}
			return true, replies, false
		}
	}
	protocol := binding.IsProtocol(packet)
	return protocol, replies, protocol
}

func (s *Server) writeStatusLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			s.queueStatusLocked()
			s.mu.Unlock()
		}
	}
}

func (s *Server) queueStatusLocked() {
	if s.cfg.StatusPath == "" {
		return
	}
	st := status{
		Circuit: s.cfg.Circuit, Sites: map[string]siteStatus{},
		LocalIdentity: sanitizedCertificateStatus(s.localControl),
		Forward:       map[string]uint64{"site-a": s.forwardA, "site-b": s.forwardB},
		ForwardBytes:  map[string]uint64{"site-a": s.forwardABytes, "site-b": s.forwardBBytes},
		Dropped:       s.dropped, DroppedBytes: s.droppedBytes, RejectedControl: s.rejectedControl,
		StatusFailures: s.statusWriteFailures.Load(), Updated: time.Now().UTC(),
	}
	for name, l := range s.legs {
		controlState, udpState := "offline", "unbound"
		authorized := legAuthorizedAt(l, time.Now())
		if authorized {
			controlState = "authenticated"
		}
		if authorized && l.bound && l.pendingAddr != nil {
			udpState = "rebinding"
		} else if authorized && l.bound {
			udpState = "bound"
		} else if authorized && l.pendingAddr != nil {
			udpState = "challenging"
		}
		st.Sites[name] = siteStatus{
			Control: controlState, UDP: udpState,
			ControlIdentity: sanitizedCertificateStatus(l.verified),
		}
	}
	select {
	case <-s.statusQueue:
	default:
	}
	select {
	case s.statusQueue <- st:
	default:
	}
}

func (s *Server) statusWriter(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case st := <-s.statusQueue:
			if err := s.writeStatus(st); err != nil {
				s.statusWriteFailures.Add(1)
			}
		}
	}
}

func (s *Server) writeStatus(st status) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	directory := filepath.Dir(s.cfg.StatusPath)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(directory, ".campus-link-status.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0640); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.cfg.StatusPath)
}

func sanitizedCertificateStatus(verified identity.Verified) *certificateStatus {
	slot := identity.PinSlotName(verified.PinSlot)
	if verified.NotAfter.IsZero() || (slot != "current" && slot != "next") {
		return nil
	}
	return &certificateStatus{Expires: verified.NotAfter.UTC().Format(time.RFC3339), PinSlot: slot}
}

func (s *Server) authorizedSite(state tls.ConnectionState) (string, error) {
	site, _, err := s.authorizedSiteVerified(state)
	return site, err
}

func (s *Server) authorizedSiteVerified(state tls.ConnectionState) (string, identity.Verified, error) {
	matched := ""
	var matchedVerified identity.Verified
	for _, site := range []string{"site-a", "site-b"} {
		verified, err := identity.VerifyConnection(state, s.controlRequirements[site])
		if err != nil {
			continue
		}
		if matched != "" {
			return "", identity.Verified{}, identity.ErrPeerIdentity
		}
		matched = site
		matchedVerified = verified
	}
	if matched == "" {
		return "", identity.Verified{}, identity.ErrPeerIdentity
	}
	return matched, matchedVerified, nil
}

func (s *Server) relayTLS() (*tls.Config, error) {
	material, err := s.validatedTLSMaterial(time.Now())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.localControl = material.localControl
	s.mu.Unlock()
	return material.config, nil
}

func (s *Server) relayTLSFromMaterial(cert tls.Certificate, pool *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		VerifyConnection: func(state tls.ConnectionState) error {
			_, err := s.authorizedSite(state)
			return err
		},
	}
}

func (s *Server) localControlIdentity() identity.Verified {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.localControl
}

func sameAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}

func cloneAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), a.IP...), Port: a.Port, Zone: a.Zone}
}
