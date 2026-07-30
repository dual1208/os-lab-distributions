package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	quic "github.com/quic-go/quic-go"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/binding"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/datapath"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/nonquic"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/rendezvous"
	cltun "github.com/dual1208/os-lab-distributions/campus-link/internal/tun"
)

type Runner struct {
	cfg                   config.Edge
	version               string
	sent                  atomic.Uint64
	received              atomic.Uint64
	dropped               atomic.Uint64
	bindingRejected       atomic.Uint64
	rejectedPlans         atomic.Uint64
	directFailures        atomic.Uint64
	statusFailures        atomic.Uint64
	planEpoch             atomic.Uint64
	mu                    sync.Mutex
	statusMu              sync.Mutex
	statusWake            chan struct{}
	state                 edgeState
	localControl          identity.Verified
	peerControl           identity.Verified
	localData             identity.Verified
	pathPeerData          map[pathIdentityKey]identity.Verified
	certificateCutoff     time.Time
	pathSnapshot          datapath.Snapshot
	pathMux               *datapath.Mux
	transitionMux         *datapath.Mux
	transitionMuxSet      bool
	muxPathTransitions    uint64
	selectedTransitions   uint64
	identityTransitions   uint64
	identityTransition    identityTransitionState
	identityTransitionSet bool
	statusGeneration      uint64
	relayGeneration       string
	planNamespace         string
	blockedPlanNamespace  string
	planSessionSerial     uint64
	activePlanSession     uint64
	planSessionAuthority  context.Context
	planSessionCancel     context.CancelFunc
	clockAuthority        clockAuthorityState
	plans                 chan authorizedPlan
	rememberedPlan        *rememberedPlan
	controlRequirements   identity.Requirements
	dataRequirements      identity.Requirements
}

const controlRegistrationWindow = 10 * time.Second

type edgeState struct {
	Site                    string                `json:"site"`
	Control                 string                `json:"control"`
	UDP                     string                `json:"udp"`
	QUIC                    string                `json:"quic"`
	TUN                     string                `json:"tun"`
	StatusGeneration        uint64                `json:"status_generation"`
	SelectedPathTransitions uint64                `json:"selected_path_transitions"`
	IdentityTransitions     uint64                `json:"identity_transitions"`
	Path                    edgePathStatus        `json:"path"`
	ControlIdentity         *planeIdentityStatus  `json:"control_identity,omitempty"`
	DataIdentity            *dataIdentityStatus   `json:"data_identity,omitempty"`
	Sent                    uint64                `json:"sent_packets"`
	Received                uint64                `json:"received_packets"`
	Dropped                 uint64                `json:"dropped_packets"`
	BindingRejected         uint64                `json:"rejected_binding_packets"`
	RejectedPlans           uint64                `json:"rejected_rendezvous_plans"`
	DirectFailures          uint64                `json:"direct_path_failures"`
	StatusFailures          uint64                `json:"status_write_failures"`
	Clock                   edgeClockStatus       `json:"clock"`
	RelayTelemetry          *relayTelemetryStatus `json:"relay_telemetry,omitempty"`
	LastUpdate              time.Time             `json:"updated"`
}

type edgeClockStatus struct {
	Synchronized         bool   `json:"synchronized"`
	AbsoluteOffsetMillis uint64 `json:"absolute_offset_millis"`
	UncertaintyMillis    uint64 `json:"uncertainty_millis"`
}

type relayTelemetryStatus struct {
	ControlSession   uint64                     `json:"control_session"`
	Sequence         uint64                     `json:"sequence"`
	ForwardedPackets relayForwardedPacketStatus `json:"forwarded_packets"`
	ForwardedBytes   relayForwardedPacketStatus `json:"forwarded_bytes"`
	DroppedPackets   uint64                     `json:"dropped_packets"`
	DroppedBytes     uint64                     `json:"dropped_bytes"`
}

type relayForwardedPacketStatus struct {
	SiteA uint64 `json:"site-a"`
	SiteB uint64 `json:"site-b"`
}

type edgePathStatus struct {
	Selected         string `json:"selected"`
	DirectState      string `json:"direct_state"`
	DirectRequired   bool   `json:"direct_required"`
	DirectEpoch      uint64 `json:"direct_epoch"`
	DirectInstance   uint64 `json:"direct_instance"`
	RelayHealthy     bool   `json:"relay_healthy"`
	DirectHealthy    bool   `json:"direct_healthy"`
	RelaySent        uint64 `json:"relay_sent_packets"`
	DirectSent       uint64 `json:"direct_sent_packets"`
	RelayReceived    uint64 `json:"relay_received_packets"`
	DirectReceived   uint64 `json:"direct_received_packets"`
	Fallbacks        uint64 `json:"fallbacks"`
	InvalidPackets   uint64 `json:"invalid_packets"`
	DuplicatePackets uint64 `json:"duplicate_packets"`
	QueueDrops       uint64 `json:"queue_drops"`
	DirectProgress   uint64 `json:"direct_progress_acknowledgements"`
	WatchdogFailures uint64 `json:"direct_watchdog_failures"`
}

type planeIdentityStatus struct {
	Local *certificateStatus `json:"local,omitempty"`
	Peer  *certificateStatus `json:"peer,omitempty"`
}

type dataIdentityStatus struct {
	Local       *certificateStatus `json:"local,omitempty"`
	Peer        *certificateStatus `json:"peer,omitempty"`
	Path        string             `json:"path"`
	DirectEpoch uint64             `json:"direct_epoch"`
}

// pathIdentityKey is deliberately scoped to both one mux lifetime and one
// non-reusable path instance. A path epoch cannot identify a same-epoch retry,
// and a new mux may restart its local instance counter.
type pathIdentityKey struct {
	mux        *datapath.Mux
	path       datapath.Selected
	instanceID uint64
}

type identityTransitionState struct {
	localControl identity.Verified
	peerControl  identity.Verified
	localData    identity.Verified
	peerData     identity.Verified
	selected     datapath.Selected
	directEpoch  uint64
	instanceID   uint64
}

type certificateStatus struct {
	Expires string `json:"expires"`
	PinSlot string `json:"pin_slot"`
}

func New(cfg config.Edge, version string) (*Runner, error) {
	if cfg.Site != "site-a" && cfg.Site != "site-b" {
		return nil, errors.New("site must be site-a or site-b")
	}
	if cfg.Role != "client" && cfg.Role != "server" {
		return nil, errors.New("role must be client or server")
	}
	if (cfg.Site == "site-a" && cfg.Role != "client") || (cfg.Site == "site-b" && cfg.Role != "server") {
		return nil, errors.New("site-a must be the client and site-b must be the server")
	}
	if cfg.Circuit == "" || cfg.Generation == "" || cfg.RelayAddress == "" || cfg.ControlServerName == "" ||
		!control.ValidDeploymentID(cfg.DeploymentID) {
		return nil, errors.New("circuit, generation, relay address, and control server name are required")
	}
	if !control.ValidSourceVersion(version) {
		return nil, errors.New("source version must be canonical ASCII")
	}
	expectedLocalPrefix, expectedRemotePrefix := config.CampusSiteAPrefix, config.CampusSiteBPrefix
	if cfg.Site == "site-b" {
		expectedLocalPrefix, expectedRemotePrefix = expectedRemotePrefix, expectedLocalPrefix
	}
	if cfg.Prefix != expectedLocalPrefix || cfg.RemotePrefix != expectedRemotePrefix {
		return nil, errors.New("edge prefixes do not match the fixed site-a/site-b topology")
	}
	localPrefix, err := netip.ParsePrefix(cfg.Prefix)
	if err != nil || !localPrefix.Addr().Is4() {
		return nil, errors.New("valid local IPv4 prefix is required")
	}
	remotePrefix, err := netip.ParsePrefix(cfg.RemotePrefix)
	if err != nil || !remotePrefix.Addr().Is4() || localPrefix.Overlaps(remotePrefix) {
		return nil, errors.New("valid non-overlapping remote IPv4 prefix is required")
	}
	if cfg.Role == "client" && cfg.DataServerName == "" {
		return nil, errors.New("client data server identity is required")
	}
	controlURI, err := expectedIdentityURI(cfg.Circuit, "relay", "control")
	if err != nil {
		return nil, err
	}
	controlRequirements, err := authorizationRequirements(cfg.ControlIdentity, controlURI, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err != nil {
		return nil, fmt.Errorf("invalid control identity authorization: %w", err)
	}
	dataURI, err := expectedIdentityURI(cfg.Circuit, peerSite(cfg.Site), "data")
	if err != nil {
		return nil, err
	}
	dataRequirements, err := authorizationRequirements(cfg.DataIdentity, dataURI, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	if err != nil {
		return nil, fmt.Errorf("invalid data identity authorization: %w", err)
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1200
	}
	if cfg.MTU != 1200 {
		return nil, errors.New("current no-fragmentation profile requires MTU 1200")
	}
	return &Runner{
		cfg: cfg, version: version, plans: make(chan authorizedPlan, 1),
		statusWake:          make(chan struct{}, 1),
		controlRequirements: controlRequirements, dataRequirements: dataRequirements,
		state: edgeState{Site: cfg.Site, Control: "offline", UDP: "unbound", QUIC: "idle", TUN: "down",
			Path: edgePathStatus{Selected: "none", DirectState: "idle", DirectRequired: true}},
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

func peerSite(site string) string {
	if site == "site-a" {
		return "site-b"
	}
	return "site-a"
}

func (r *Runner) Run(ctx context.Context) error {
	material, err := r.validatedTLSMaterial(time.Now())
	if err != nil {
		return fmt.Errorf("configuration preflight: %w", err)
	}
	controlTLS, dataTLS := material.controlTLS, material.dataTLS
	processCutoff, err := localRuntimeCutoff(time.Now(), material.localControl, material.localData)
	if err != nil {
		return fmt.Errorf("local certificate lifetime: %w", err)
	}
	r.setLocalIdentities(material.localControl, material.localData)
	r.setCertificateCutoff(processCutoff)
	statusCtx, cancelStatus := context.WithCancel(ctx)
	defer cancelStatus()
	go r.writeStatusLoop(statusCtx)
	deadlineCtx, cancelDeadline := context.WithDeadline(ctx, processCutoff)
	defer cancelDeadline()
	dataCtx, cancelDataCause := context.WithCancelCause(deadlineCtx)
	cancelData := func() { cancelDataCause(context.Canceled) }
	defer cancelData()
	cutoffGuard, err := identity.GuardCertificateCutoff(dataCtx, processCutoff, func() {
		cancelDataCause(identity.ErrCertificateCutoff)
	})
	if err != nil {
		return fmt.Errorf("local certificate cutoff guard: %w", err)
	}
	defer cutoffGuard.Stop()
	r.setState("offline", "unbound", "idle", "down")
	defer r.setState("offline", "unbound", "idle", "down")
	relayUDP, err := net.ResolveUDPAddr("udp", r.cfg.RelayAddress)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}
	defer udp.Close()
	transport := &quic.Transport{Conn: udp}
	defer transport.Close()
	dispatcher, err := nonquic.New(dataCtx, transport)
	if err != nil {
		return fmt.Errorf("non-QUIC dispatcher: %w", err)
	}
	defer dispatcher.Close()
	initialControl, err := r.connectControlWithRetry(dataCtx, controlTLS, material.localControl, dispatcher, relayUDP)
	if err != nil {
		return fmt.Errorf("control bootstrap: %w", err)
	}
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		r.superviseControl(dataCtx, controlTLS, material.localControl, dispatcher, relayUDP, initialControl)
	}()
	defer func() {
		cancelData()
		<-controlDone
	}()
	r.setDataState("handshaking", "creating")

	tunFile, err := cltun.Open(r.cfg.TunName)
	if err != nil {
		return fmt.Errorf("open TUN: %w", err)
	}
	defer tunFile.Close()
	r.setDataState("handshaking", "ready")

	quicConfig := &quic.Config{EnableDatagrams: true, KeepAlivePeriod: 3 * time.Second, MaxIdleTimeout: 12 * time.Second}
	var acceptor *quicAcceptDispatcher
	if r.cfg.Role == "server" {
		listener, err := transport.Listen(dataTLS, quicConfig)
		if err != nil {
			return err
		}
		defer listener.Close()
		acceptor, err = newQUICAcceptDispatcher(dataCtx, listener, relayUDP.AddrPort())
		if err != nil {
			return fmt.Errorf("QUIC accept classifier: %w", err)
		}
		defer acceptor.Close()
	}
	relayCandidate, err := r.openRelayConnection(
		dataCtx, transport, acceptor, dataTLS, quicConfig, relayUDP, material.localData,
	)
	if err != nil {
		return fmt.Errorf("relay data path: %w", err)
	}
	mux, err := r.newRelayMux(dataCtx, r.cfg.MTU, relayCandidate)
	if err != nil {
		_ = relayCandidate.connection.Close("data path mux rejected")
		return fmt.Errorf("data path mux: %w", err)
	}
	defer mux.Close()
	defer r.setPathMux(nil)
	go r.observePath(dataCtx, mux)
	punchLease, err := dispatcher.AcquireRendezvous(dataCtx)
	if err != nil {
		return fmt.Errorf("rendezvous mailbox: %w", err)
	}
	defer punchLease.Release()
	reconnectRelay := func(reconnectCtx context.Context) (relayPathCandidate, error) {
		return r.openRelayConnection(
			reconnectCtx, transport, acceptor, dataTLS, quicConfig, relayUDP, material.localData,
		)
	}
	relaySupervisorErr := make(chan error, 1)
	relaySupervisorDone := make(chan struct{})
	go func() {
		defer close(relaySupervisorDone)
		if err := r.superviseRelay(dataCtx, mux, reconnectRelay); err != nil && dataCtx.Err() == nil {
			relaySupervisorErr <- err
		}
	}()
	defer func() {
		cancelData()
		<-relaySupervisorDone
	}()
	go r.directWorker(dataCtx, transport, punchLease, acceptor, dataTLS, quicConfig, mux, material.localData)
	r.setDataState("active", "ready")
	err = r.bridge(dataCtx, mux, tunFile, nil, dispatcher.Errors(), relaySupervisorErr)
	dataContextErr := context.Cause(dataCtx)
	cancelData()
	if err == nil && ctx.Err() == nil {
		if errors.Is(dataContextErr, context.DeadlineExceeded) || errors.Is(dataContextErr, identity.ErrCertificateCutoff) {
			err = errors.New("local certificate rotation deadline reached")
		}
	}
	return err
}

func (r *Runner) bridge(
	ctx context.Context,
	mux *datapath.Mux,
	tunFile *os.File,
	_ <-chan error,
	dispatcherErr <-chan error,
	relaySupervisorErrors ...<-chan error,
) error {
	if mux == nil || len(relaySupervisorErrors) > 1 {
		return datapath.ErrNoHealthyPath
	}
	var relaySupervisorErr <-chan error
	if len(relaySupervisorErrors) == 1 {
		relaySupervisorErr = relaySupervisorErrors[0]
	}
	localPrefix, err := netip.ParsePrefix(r.cfg.Prefix)
	if err != nil {
		return err
	}
	remotePrefix, err := netip.ParsePrefix(r.cfg.RemotePrefix)
	if err != nil {
		return err
	}
	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, r.cfg.MTU+1)
		for {
			n, err := tunFile.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			if n > r.cfg.MTU {
				r.dropped.Add(1)
				continue
			}
			total, err := cltun.AuthorizeIPv4(buf[:n], localPrefix, remotePrefix)
			if err != nil {
				r.dropped.Add(1)
				continue
			}
			if err := mux.SendPacketContext(ctx, buf[:total]); err != nil {
				errCh <- err
				return
			}
			r.sent.Add(1)
		}
	}()
	go func() {
		for {
			packet, err := mux.ReceivePacket(ctx)
			if err != nil {
				errCh <- err
				return
			}
			if len(packet) > r.cfg.MTU {
				r.dropped.Add(1)
				continue
			}
			total, err := cltun.AuthorizeIPv4(packet, remotePrefix, localPrefix)
			if err != nil {
				r.dropped.Add(1)
				continue
			}
			written, err := tunFile.Write(packet[:total])
			if err != nil {
				errCh <- err
				return
			}
			if written != total {
				errCh <- io.ErrShortWrite
				return
			}
			r.received.Add(1)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			return err
		case err := <-dispatcherErr:
			return err
		case err := <-mux.Errors():
			return err
		case err := <-relaySupervisorErr:
			if err == nil {
				return errors.New("relay recovery supervisor stopped")
			}
			return err
		}
	}
}

func (r *Runner) writeStatusLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer func() { r.recordStatusWrite(r.writeStatusNow()) }()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.statusWake:
			r.recordStatusWrite(r.writeStatusNow())
		case <-ticker.C:
			r.recordStatusWrite(r.writeStatusNow())
		}
	}
}

func bindUDP(ctx context.Context, conn *net.UDPConn, relay *net.UDPAddr, site string, token []byte) error {
	return bindUDPWithTimeouts(ctx, conn, relay, site, token, 30*time.Second, 2*time.Second)
}

func bindUDPWithTimeouts(ctx context.Context, conn *net.UDPConn, relay *net.UDPAddr, site string, token []byte, overallTimeout, retryTimeout time.Duration) error {
	if conn == nil {
		return errors.New("UDP tuple binding requires a socket")
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	return bindNonQUICWithTimeouts(ctx, udpNonQUICIO{conn: conn}, relay, site, token, overallTimeout, retryTimeout)
}

func bindNonQUIC(ctx context.Context, conn rendezvous.NonQUICPacketIO, relay *net.UDPAddr, site string, token []byte) error {
	return bindNonQUICWithTimeouts(ctx, conn, relay, site, token, 30*time.Second, 2*time.Second)
}

func bindNonQUICCount(ctx context.Context, conn rendezvous.NonQUICPacketIO, relay *net.UDPAddr, site string, token []byte, rejected *atomic.Uint64) error {
	return bindNonQUICWithTimeoutsCount(ctx, conn, relay, site, token, 30*time.Second, 2*time.Second, rejected)
}

func bindNonQUICWithTimeouts(ctx context.Context, conn rendezvous.NonQUICPacketIO, relay *net.UDPAddr, site string, token []byte, overallTimeout, retryTimeout time.Duration) error {
	return bindNonQUICWithTimeoutsCount(ctx, conn, relay, site, token, overallTimeout, retryTimeout, nil)
}

func bindNonQUICWithTimeoutsCount(ctx context.Context, conn rendezvous.NonQUICPacketIO, relay *net.UDPAddr, site string, token []byte, overallTimeout, retryTimeout time.Duration, rejected *atomic.Uint64) error {
	if ctx == nil || conn == nil || relay == nil || overallTimeout <= 0 || retryTimeout <= 0 {
		return errors.New("UDP tuple binding requires positive timeouts")
	}
	sequence := uint64(1)
	requestPacket, request, err := binding.NewRequest(site, sequence, token)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(overallTimeout)
	last := requestPacket
	var challenge binding.Metadata
	haveChallenge := false
	requestSends := 0
	buf := make([]byte, 256)
	nextSend := time.Now()
	reject := func() {
		if rejected != nil {
			rejected.Add(1)
		}
	}
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		now := time.Now()
		if !now.Before(nextSend) {
			if !haveChallenge && requestSends > 0 && requestSends%3 == 0 {
				sequence++
				requestPacket, request, err = binding.NewRequest(site, sequence, token)
				if err != nil {
					return err
				}
				last = requestPacket
			}
			written, err := conn.WriteTo(last, relay)
			if err != nil {
				return err
			}
			if written != len(last) {
				return io.ErrShortWrite
			}
			if !haveChallenge {
				requestSends++
			}
			for !nextSend.After(now) {
				nextSend = nextSend.Add(retryTimeout)
			}
		}
		readDeadline := nextSend
		if readDeadline.After(deadline) {
			readDeadline = deadline
		}
		readCtx, cancelRead := context.WithDeadline(ctx, readDeadline)
		n, source, err := conn.ReadNonQUICPacket(readCtx, buf)
		cancelRead()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				continue
			}
			return err
		}
		src, ok := source.(*net.UDPAddr)
		if !ok || src.IP == nil || src.Port <= 0 || src.Port > 65535 {
			reject()
			continue
		}
		if !src.IP.Equal(relay.IP) || src.Port != relay.Port {
			reject()
			continue
		}
		if candidate, ok := binding.ParseChallenge(buf[:n], token); ok {
			if !candidate.SameRequest(request) {
				reject()
				continue
			}
			last, err = binding.NewResponse(candidate, token)
			if err != nil {
				return err
			}
			challenge = candidate
			haveChallenge = true
			nextSend = time.Now()
			continue
		}
		if ready, ok := binding.ParseReady(buf[:n], token); ok && haveChallenge && ready.SameTransaction(challenge) {
			return nil
		}
		reject()
	}
	return errors.New("UDP tuple binding timed out")
}

type udpNonQUICIO struct {
	conn *net.UDPConn
}

func (u udpNonQUICIO) WriteTo(packet []byte, address net.Addr) (int, error) {
	udpAddress, ok := address.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("UDP tuple binding requires a UDP destination")
	}
	return u.conn.WriteToUDP(packet, udpAddress)
}

func (u udpNonQUICIO) ReadNonQUICPacket(ctx context.Context, packet []byte) (int, net.Addr, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0, nil, errors.New("bounded UDP tuple read requires a deadline")
	}
	if err := u.conn.SetReadDeadline(deadline); err != nil {
		return 0, nil, err
	}
	n, address, err := u.conn.ReadFromUDP(packet)
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		if ctx.Err() != nil {
			return 0, nil, ctx.Err()
		}
		return 0, nil, context.DeadlineExceeded
	}
	return n, address, err
}

func (r *Runner) heartbeat(ctx context.Context, cancel context.CancelFunc, conn net.Conn, enc *json.Encoder, dec *control.Decoder, errCh chan<- error) {
	r.heartbeatUntil(ctx, cancel, conn, enc, dec, errCh, time.Time{})
}

func (r *Runner) heartbeatUntil(ctx context.Context, cancel context.CancelFunc, conn net.Conn, enc *json.Encoder, dec *control.Decoder, errCh chan<- error, cutoff time.Time) {
	r.heartbeatPlanSessionWithIntervalUntil(ctx, cancel, conn, enc, dec, errCh, planSessionLease{}, 5*time.Second, cutoff)
}

func (r *Runner) heartbeatWithInterval(ctx context.Context, cancel context.CancelFunc, conn net.Conn, enc *json.Encoder, dec *control.Decoder, errCh chan<- error, interval time.Duration) {
	r.heartbeatWithIntervalUntil(ctx, cancel, conn, enc, dec, errCh, interval, time.Time{})
}

func (r *Runner) heartbeatWithIntervalUntil(ctx context.Context, cancel context.CancelFunc, conn net.Conn, enc *json.Encoder, dec *control.Decoder, errCh chan<- error, interval time.Duration, cutoff time.Time) {
	r.heartbeatPlanSessionWithIntervalUntil(ctx, cancel, conn, enc, dec, errCh, planSessionLease{}, interval, cutoff)
}

func (r *Runner) heartbeatPlanSessionUntil(ctx context.Context, cancel context.CancelFunc, conn net.Conn, enc *json.Encoder, dec *control.Decoder, errCh chan<- error, lease planSessionLease, cutoff time.Time) {
	r.heartbeatPlanSessionWithIntervalUntil(ctx, cancel, conn, enc, dec, errCh, lease, 5*time.Second, cutoff)
}

func (r *Runner) heartbeatPlanSessionWithIntervalUntil(ctx context.Context, cancel context.CancelFunc, conn net.Conn, enc *json.Encoder, dec *control.Decoder, errCh chan<- error, lease planSessionLease, interval time.Duration, cutoff time.Time) {
	if interval <= 0 {
		failControl(cancel, errCh, errors.New("invalid heartbeat interval"))
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var sequence uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if sequence == ^uint64(0) {
				failControl(cancel, errCh, errors.New("control heartbeat sequence exhausted"))
				return
			}
			sequence++
			operationCutoff := cutoff
			writeDeadline, err := controlIODeadline(time.Now(), 5*time.Second, operationCutoff)
			if err != nil {
				failControl(cancel, errCh, fmt.Errorf("control heartbeat lifetime: %w", err))
				return
			}
			if err := conn.SetWriteDeadline(writeDeadline); err != nil {
				failControl(cancel, errCh, fmt.Errorf("set control heartbeat write deadline: %w", err))
				return
			}
			exchange, err := newClockExchange(sequence, time.Now())
			if err != nil {
				failControl(cancel, errCh, fmt.Errorf("capture control heartbeat clock: %w", err))
				return
			}
			if err := enc.Encode(exchange.heartbeat()); err != nil {
				failControl(cancel, errCh, fmt.Errorf("control heartbeat write: %w", err))
				return
			}
			operationCutoff = cutoff
			readDeadline, err := controlIODeadline(time.Now(), 5*time.Second, operationCutoff)
			if err != nil {
				failControl(cancel, errCh, fmt.Errorf("control heartbeat lifetime: %w", err))
				return
			}
			if err := conn.SetReadDeadline(readDeadline); err != nil {
				failControl(cancel, errCh, fmt.Errorf("set control heartbeat read deadline: %w", err))
				return
			}
			var ack control.HeartbeatAck
			if err := dec.Decode(&ack); err != nil {
				failControl(cancel, errCh, fmt.Errorf("control heartbeat acknowledgement: %w", err))
				return
			}
			receivedAt := time.Now()
			if ack.Type != "heartbeat-ack" || ack.Sequence != sequence {
				failControl(cancel, errCh, errors.New("invalid control heartbeat acknowledgement"))
				return
			}
			if lease.valid() {
				if err := r.recordClockSample(lease, exchange, ack, receivedAt); err != nil {
					if errors.Is(err, errClockAuthorityRevoked) {
						failControl(cancel, errCh, err)
						return
					}
					log.Printf("authenticated clock sample rejected: %v", err)
					continue
				}
			} else if _, err := evaluateClockExchange(exchange, ack, receivedAt); err != nil {
				failControl(cancel, errCh, err)
				return
			}
			if lease.valid() {
				if err := r.recordRelayTelemetry(lease, sequence, ack.Telemetry); err != nil {
					failControl(cancel, errCh, fmt.Errorf("invalid authenticated relay telemetry: %w", err))
					return
				}
			}
			if ack.Plan != nil {
				if err := r.acceptRendezvousPlan(*ack.Plan, receivedAt); err != nil {
					r.rejectedPlans.Add(1)
					log.Printf("rendezvous plan rejected")
				}
			}
		}
	}
}

func controlIODeadline(now time.Time, timeout time.Duration, cutoff time.Time) (time.Time, error) {
	if cutoff.IsZero() {
		if now.IsZero() || timeout <= 0 {
			return time.Time{}, errors.New("invalid control I/O deadline")
		}
		return now.Add(timeout), nil
	}
	return identity.BoundedDeadline(now, timeout, cutoff)
}

func (r *Runner) acceptRendezvousPlan(message control.RendezvousPlan, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	relayGeneration := r.relayGeneration
	if r.activePlanSession == 0 || r.planSessionAuthority == nil || r.planSessionAuthority.Done() == nil ||
		!control.ValidRelayGeneration(relayGeneration) {
		return errors.New("authenticated relay generation unavailable")
	}
	lease := planSessionLease{
		namespace: r.planNamespace, serial: r.activePlanSession, authority: r.planSessionAuthority,
	}
	if !lease.valid() {
		return errors.New("authenticated plan session unavailable")
	}
	select {
	case <-lease.authority.Done():
		return errors.New("authenticated plan session revoked")
	default:
	}
	if !r.clockSynchronizedLocked(lease, now) {
		return errors.New("authenticated clock sample unavailable or stale")
	}
	current := r.planEpoch.Load()
	if message.PathEpoch < current {
		return errors.New("rendezvous plan path epoch rollback")
	}
	plan, err := rendezvous.ValidatePlan(message, rendezvous.PlanExpect{
		Circuit: r.cfg.Circuit, Version: r.version, DeploymentID: r.cfg.DeploymentID,
		RelayGeneration: relayGeneration, Generation: r.cfg.Generation, MinPathEpoch: current,
		AllowMinEpoch: true, Now: now,
	})
	if err != nil {
		return fmt.Errorf("invalid rendezvous plan: %w", err)
	}
	if (r.cfg.Site == "site-a" && plan.Role != rendezvous.RoleSender) ||
		(r.cfg.Site == "site-b" && plan.Role != rendezvous.RoleReceiver) {
		return errors.New("rendezvous plan role does not match fixed site role")
	}
	if r.plans == nil {
		return errors.New("rendezvous plan mailbox unavailable")
	}
	if message.PathEpoch == current {
		remembered := r.rememberedPlan
		if remembered == nil || remembered.authorized.PathEpoch != current ||
			remembered.authorized.lease.namespace != lease.namespace ||
			!sameRendezvousPlanMessage(remembered.message, message) ||
			!sameValidatedPlan(remembered.authorized.Plan, plan) {
			return errors.New("rendezvous plan conflicts with remembered path epoch")
		}
		if samePlanSession(remembered.authorized.lease, lease) {
			return nil
		}
		candidate := authorizedPlan{Plan: plan, lease: lease, leaseRebind: true}
		r.drainPlansLocked()
		select {
		case r.plans <- candidate:
			r.rememberedPlan = &rememberedPlan{
				message: cloneRendezvousPlanMessage(message), authorized: candidate,
			}
			return nil
		default:
			return errors.New("rendezvous plan mailbox unavailable")
		}
	}
	select {
	case <-r.plans:
	default:
	}
	candidate := authorizedPlan{Plan: plan, lease: lease}
	r.planEpoch.Store(plan.PathEpoch)
	select {
	case r.plans <- candidate:
		r.rememberedPlan = &rememberedPlan{
			message: cloneRendezvousPlanMessage(message), authorized: candidate,
		}
	default:
		r.planEpoch.Store(current)
		return errors.New("rendezvous plan mailbox unavailable")
	}
	return nil
}

func (r *Runner) beginPlanSession(relayGeneration string) planSessionLease {
	namespace, err := planAuthorityNamespace(r.version, r.cfg.DeploymentID, relayGeneration)
	if err != nil {
		return planSessionLease{}
	}
	authority, cancelAuthority := context.WithCancel(context.Background())
	r.mu.Lock()
	priorCancel := r.planSessionCancel
	r.drainPlansLocked()
	if r.planSessionSerial == ^uint64(0) {
		r.relayGeneration = ""
		r.activePlanSession = 0
		r.planSessionAuthority = nil
		r.planSessionCancel = nil
		r.state.RelayTelemetry = nil
		r.rememberedPlan = nil
		r.resetClockAuthorityLocked()
		r.mu.Unlock()
		cancelAuthority()
		if priorCancel != nil {
			priorCancel()
		}
		r.writeStatus()
		return planSessionLease{}
	}
	if r.planNamespace != "" && r.planNamespace != namespace {
		r.planEpoch.Store(0)
		r.rememberedPlan = nil
	}
	r.planSessionSerial++
	r.planNamespace = namespace
	r.relayGeneration = relayGeneration
	r.activePlanSession = r.planSessionSerial
	r.planSessionAuthority = authority
	r.planSessionCancel = cancelAuthority
	r.state.RelayTelemetry = nil
	r.resetClockAuthorityLocked()
	lease := planSessionLease{namespace: namespace, serial: r.activePlanSession, authority: authority}
	r.mu.Unlock()
	if priorCancel != nil {
		priorCancel()
	}
	return lease
}

func (r *Runner) endPlanSession(lease planSessionLease) {
	r.mu.Lock()
	if !r.planSessionCurrentLocked(lease) {
		r.mu.Unlock()
		return
	}
	r.drainPlansLocked()
	cancelAuthority := r.planSessionCancel
	r.relayGeneration = ""
	r.activePlanSession = 0
	r.planSessionAuthority = nil
	r.planSessionCancel = nil
	r.state.RelayTelemetry = nil
	r.resetClockAuthorityLocked()
	r.mu.Unlock()
	if cancelAuthority != nil {
		cancelAuthority()
	}
	r.writeStatus()
}

func (r *Runner) drainPlansLocked() {
	for {
		select {
		case <-r.plans:
		default:
			return
		}
	}
}

func failControl(cancel context.CancelFunc, errCh chan<- error, err error) {
	cancel()
	select {
	case errCh <- err:
	default:
	}
}

func (r *Runner) dataTLS() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(r.cfg.DataCert, r.cfg.DataKey)
	if err != nil {
		return nil, err
	}
	pool, err := certPool(r.cfg.DataCA)
	if err != nil {
		return nil, err
	}
	return r.dataTLSFromMaterial(cert, pool), nil
}

func (r *Runner) dataTLSFromMaterial(cert tls.Certificate, pool *x509.CertPool) *tls.Config {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"campus-link/1"},
		VerifyConnection: func(state tls.ConnectionState) error {
			_, err := identity.VerifyConnection(state, r.dataRequirements)
			return err
		},
	}
	if r.cfg.Role == "server" {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = pool
	} else {
		cfg.RootCAs = pool
		cfg.ServerName = r.cfg.DataServerName
	}
	return cfg
}

func clientTLS(certPath, keyPath, caPath, serverName string, requirements identity.Requirements) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	pool, err := certPool(caPath)
	if err != nil {
		return nil, err
	}
	return clientTLSFromMaterial(cert, pool, serverName, requirements), nil
}

func clientTLSFromMaterial(cert tls.Certificate, pool *x509.CertPool, serverName string, requirements identity.Requirements) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: serverName,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		VerifyConnection: func(state tls.ConnectionState) error {
			_, err := identity.VerifyConnection(state, requirements)
			return err
		},
	}
}

func certPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("invalid CA")
	}
	return pool, nil
}

func (r *Runner) setState(controlState, udpState, quicState, tunState string) {
	r.mu.Lock()
	r.state.Control, r.state.UDP, r.state.QUIC, r.state.TUN = controlState, udpState, quicState, tunState
	r.mu.Unlock()
	r.writeStatus()
	log.Printf("state control=%s udp=%s quic=%s tun=%s", controlState, udpState, quicState, tunState)
}

func (r *Runner) setDirectAttempt(state string) {
	r.mu.Lock()
	r.state.Path.DirectState = state
	r.mu.Unlock()
	r.writeStatus()
}

func addStickyTransition(total *uint64, delta uint64) {
	if delta > ^uint64(0)-*total {
		*total = ^uint64(0)
		return
	}
	*total += delta
}

func (r *Runner) notePathTransitionsLocked(mux *datapath.Mux, snapshot datapath.Snapshot) uint64 {
	delta := uint64(0)
	if !r.transitionMuxSet {
		r.transitionMuxSet = true
		r.transitionMux = mux
		r.muxPathTransitions = snapshot.SelectedPathTransitions
		delta = snapshot.SelectedPathTransitions
	} else if r.transitionMux != mux {
		delta = 1
		r.transitionMux = mux
		r.muxPathTransitions = snapshot.SelectedPathTransitions
		addStickyTransition(&delta, snapshot.SelectedPathTransitions)
	} else if snapshot.SelectedPathTransitions < r.muxPathTransitions {
		// A same-authority regression is impossible for a conforming mux. Make
		// the anomaly sticky so a qualification baseline cannot silently reuse it.
		delta = 1
		r.muxPathTransitions = snapshot.SelectedPathTransitions
	} else {
		delta = snapshot.SelectedPathTransitions - r.muxPathTransitions
		r.muxPathTransitions = snapshot.SelectedPathTransitions
	}
	addStickyTransition(&r.selectedTransitions, delta)
	// Every selected authority change also changes the selected data binding.
	// Carry the mux's sticky delta into identity evidence even if the final
	// public certificate view equals the starting view.
	addStickyTransition(&r.identityTransitions, delta)
	r.state.SelectedPathTransitions = r.selectedTransitions
	r.state.IdentityTransitions = r.identityTransitions
	return delta
}

func sameVerifiedIdentity(left, right identity.Verified) bool {
	return left.PinSlot == right.PinSlot && left.NotAfter.Equal(right.NotAfter)
}

func (r *Runner) noteIdentityTransitionLocked(
	mux *datapath.Mux, snapshot datapath.Snapshot, pathTransitionDelta uint64,
) {
	selected := snapshot.Selected
	directEpoch := uint64(0)
	instanceID := uint64(0)
	switch selected {
	case datapath.SelectedDirect:
		directEpoch = snapshot.DirectEpoch
		instanceID = snapshot.DirectInstanceID
	case datapath.SelectedRelay:
		instanceID = snapshot.RelayInstanceID
	default:
		selected = datapath.SelectedNone
	}
	current := identityTransitionState{
		localControl: r.localControl,
		peerControl:  r.peerControl,
		localData:    r.localData,
		peerData:     selectedPeerData(mux, snapshot, r.pathPeerData),
		selected:     selected,
		directEpoch:  directEpoch,
		instanceID:   instanceID,
	}
	if r.identityTransitionSet {
		prior := r.identityTransition
		baseIdentityChanged :=
			!sameVerifiedIdentity(prior.localControl, current.localControl) ||
				!sameVerifiedIdentity(prior.peerControl, current.peerControl) ||
				!sameVerifiedIdentity(prior.localData, current.localData)
		selectedPeerChanged := !sameVerifiedIdentity(prior.peerData, current.peerData)
		if baseIdentityChanged {
			addStickyTransition(&r.identityTransitions, 1)
		}
		if pathTransitionDelta == 0 && selectedPeerChanged {
			addStickyTransition(&r.identityTransitions, 1)
		}
	} else {
		r.identityTransitionSet = true
	}
	r.identityTransition = current
	r.state.IdentityTransitions = r.identityTransitions
}

func (r *Runner) refreshStatusTransitionsLocked() (datapath.Snapshot, *datapath.Mux) {
	mux := r.pathMux
	snapshot := r.pathSnapshot
	if mux != nil {
		snapshot = mux.Snapshot()
	} else {
		snapshot = datapath.Snapshot{
			Selected:       datapath.SelectedNone,
			DirectRequired: r.state.Path.DirectRequired,
		}
	}
	r.pathSnapshot = snapshot
	r.state.Path = pathStatus(snapshot, r.state.Path.DirectState)
	pathTransitionDelta := r.notePathTransitionsLocked(mux, snapshot)
	r.noteIdentityTransitionLocked(mux, snapshot, pathTransitionDelta)
	return snapshot, mux
}

func (r *Runner) setPathMux(mux *datapath.Mux) {
	r.mu.Lock()
	r.refreshStatusTransitionsLocked()
	prior := r.pathMux
	r.pathMux = mux
	if mux == nil {
		for key := range r.pathPeerData {
			if key.mux == prior {
				delete(r.pathPeerData, key)
			}
		}
	}
	r.refreshStatusTransitionsLocked()
	r.mu.Unlock()
}

func (r *Runner) observePath(ctx context.Context, mux *datapath.Mux) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-mux.Changes():
			r.mu.Lock()
			if r.pathMux == mux {
				// Changes is a coalescing wakeup, not evidence. A delayed queued
				// snapshot may predate a synchronous transaction refresh, so always
				// harvest the mux's live cumulative generations under Runner.mu.
				r.refreshStatusTransitionsLocked()
			}
			r.mu.Unlock()
			r.writeStatus()
		}
	}
}

func pathStatus(snapshot datapath.Snapshot, directState string) edgePathStatus {
	directInstance := snapshot.DirectInstanceID
	if snapshot.Selected != datapath.SelectedDirect || !snapshot.DirectHealthy {
		directInstance = 0
	}
	return edgePathStatus{
		Selected: string(snapshot.Selected), DirectState: directState, DirectEpoch: snapshot.DirectEpoch,
		DirectRequired: snapshot.DirectRequired,
		DirectInstance: directInstance,
		RelayHealthy:   snapshot.RelayHealthy, DirectHealthy: snapshot.DirectHealthy,
		RelaySent: snapshot.Counters.RelaySent, DirectSent: snapshot.Counters.DirectSent,
		RelayReceived: snapshot.Counters.RelayReceived, DirectReceived: snapshot.Counters.DirectReceived,
		Fallbacks: snapshot.Counters.Fallbacks, InvalidPackets: snapshot.Counters.InvalidPackets,
		DuplicatePackets: snapshot.Counters.DuplicatePacket, QueueDrops: snapshot.Counters.QueueDrops,
		DirectProgress: snapshot.Counters.DirectProgress, WatchdogFailures: snapshot.Counters.WatchdogFailure,
	}
}

func (r *Runner) setLocalIdentities(controlVerified, dataVerified identity.Verified) {
	r.mu.Lock()
	r.noteIdentityTransitionLocked(r.pathMux, r.pathSnapshot, 0)
	r.localControl, r.localData = controlVerified, dataVerified
	r.peerControl = identity.Verified{}
	r.pathPeerData = make(map[pathIdentityKey]identity.Verified)
	r.certificateCutoff = time.Time{}
	r.noteIdentityTransitionLocked(r.pathMux, r.pathSnapshot, 0)
	r.mu.Unlock()
	r.writeStatus()
}

func (r *Runner) setCertificateCutoff(cutoff time.Time) {
	r.mu.Lock()
	if r.certificateCutoff.IsZero() || (!cutoff.IsZero() && cutoff.Before(r.certificateCutoff)) {
		r.certificateCutoff = cutoff
	}
	r.mu.Unlock()
}

func (r *Runner) certificateDeadline(fallback time.Time) time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.certificateCutoff.IsZero() || (!fallback.IsZero() && fallback.Before(r.certificateCutoff)) {
		return fallback
	}
	return r.certificateCutoff
}

func (r *Runner) setPeerControl(verified identity.Verified) {
	r.mu.Lock()
	r.noteIdentityTransitionLocked(r.pathMux, r.pathSnapshot, 0)
	r.peerControl = verified
	r.noteIdentityTransitionLocked(r.pathMux, r.pathSnapshot, 0)
	r.mu.Unlock()
	r.writeStatus()
}

func (r *Runner) setRelayPeerData(mux *datapath.Mux, verified identity.Verified, instanceID uint64) {
	r.mu.Lock()
	if mux != nil && instanceID != 0 {
		r.bindPathIdentityLocked(mux, datapath.SelectedRelay, instanceID, verified)
	}
	r.mu.Unlock()
	r.writeStatus()
}

func (r *Runner) writeStatus() {
	if r.cfg.StatusPath == "" {
		return
	}
	// Observe transitions synchronously before the wakeup can coalesce with a
	// later reversal. The writer remains the only filesystem publisher.
	r.mu.Lock()
	r.refreshStatusTransitionsLocked()
	r.mu.Unlock()
	if r.statusWake != nil {
		select {
		case r.statusWake <- struct{}{}:
		default:
		}
		return
	}
	r.recordStatusWrite(r.writeStatusNow())
}

func (r *Runner) recordStatusWrite(err error) {
	if err != nil {
		r.statusFailures.Add(1)
	}
}

func (r *Runner) writeStatusNow() error {
	if r.cfg.StatusPath == "" {
		return nil
	}
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	if r.statusGeneration == ^uint64(0) {
		return errors.New("status publication generation exhausted")
	}
	r.statusGeneration++
	statusNow := time.Now()
	r.mu.Lock()
	pathSnapshot, pathMux := r.refreshStatusTransitionsLocked()
	st := r.state
	st.StatusGeneration = r.statusGeneration
	if !r.clockStatusCurrentLocked(statusNow) {
		st.Clock = edgeClockStatus{}
	}
	localControl, peerControl := r.localControl, r.peerControl
	localData := r.localData
	peerData := selectedPeerData(pathMux, pathSnapshot, r.pathPeerData)
	r.mu.Unlock()
	st.ControlIdentity = identityStatus(localControl, peerControl)
	st.DataIdentity = selectedDataIdentityStatus(localData, peerData, st.Path)
	st.Sent, st.Received, st.Dropped, st.BindingRejected, st.RejectedPlans, st.DirectFailures, st.StatusFailures, st.LastUpdate = r.sent.Load(), r.received.Load(), r.dropped.Load(), r.bindingRejected.Load(), r.rejectedPlans.Load(), r.directFailures.Load(), r.statusFailures.Load(), statusNow.UTC()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	directory := filepath.Dir(r.cfg.StatusPath)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("status directory is not a real directory")
	}
	tmp, err := os.CreateTemp(directory, ".campus-link-status.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	defer tmp.Close()
	if err := tmp.Chmod(0640); err != nil {
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, r.cfg.StatusPath)
}

func localRuntimeCutoff(now time.Time, localControl, localData identity.Verified) (time.Time, error) {
	return identity.SessionDeadline(now, localControl, localData)
}

func (r *Runner) bindPathIdentityLocked(
	mux *datapath.Mux,
	path datapath.Selected,
	instanceID uint64,
	verified identity.Verified,
	retain ...uint64,
) {
	if mux == nil || instanceID == 0 || (path != datapath.SelectedRelay && path != datapath.SelectedDirect) {
		return
	}
	r.noteIdentityTransitionLocked(r.pathMux, r.pathSnapshot, 0)
	r.bindPathIdentityMapLocked(mux, path, instanceID, verified, retain...)
	r.noteIdentityTransitionLocked(r.pathMux, r.pathSnapshot, 0)
}

func (r *Runner) bindPathIdentityMapLocked(
	mux *datapath.Mux,
	path datapath.Selected,
	instanceID uint64,
	verified identity.Verified,
	retain ...uint64,
) {
	if mux == nil || instanceID == 0 || (path != datapath.SelectedRelay && path != datapath.SelectedDirect) {
		return
	}
	if r.pathPeerData == nil {
		r.pathPeerData = make(map[pathIdentityKey]identity.Verified)
	}
	keep := map[uint64]struct{}{instanceID: {}}
	for _, id := range retain {
		if id != 0 {
			keep[id] = struct{}{}
		}
	}
	for key := range r.pathPeerData {
		if key.mux != mux {
			delete(r.pathPeerData, key)
			continue
		}
		if key.path == path {
			if _, retained := keep[key.instanceID]; !retained {
				delete(r.pathPeerData, key)
			}
		}
	}
	r.pathPeerData[pathIdentityKey{mux: mux, path: path, instanceID: instanceID}] = verified
}

func (r *Runner) deletePathIdentityLocked(mux *datapath.Mux, path datapath.Selected, instanceID uint64) {
	r.noteIdentityTransitionLocked(r.pathMux, r.pathSnapshot, 0)
	r.deletePathIdentityMapLocked(mux, path, instanceID)
	r.noteIdentityTransitionLocked(r.pathMux, r.pathSnapshot, 0)
}

func (r *Runner) deletePathIdentityMapLocked(mux *datapath.Mux, path datapath.Selected, instanceID uint64) {
	delete(r.pathPeerData, pathIdentityKey{mux: mux, path: path, instanceID: instanceID})
}

func selectedPeerData(
	mux *datapath.Mux, snapshot datapath.Snapshot, bindings map[pathIdentityKey]identity.Verified,
) identity.Verified {
	var key pathIdentityKey
	switch {
	case mux != nil && snapshot.Selected == datapath.SelectedDirect && snapshot.DirectHealthy && snapshot.DirectInstanceID != 0:
		key = pathIdentityKey{mux: mux, path: datapath.SelectedDirect, instanceID: snapshot.DirectInstanceID}
	case mux != nil && snapshot.Selected == datapath.SelectedRelay && snapshot.RelayHealthy && snapshot.RelayInstanceID != 0:
		key = pathIdentityKey{mux: mux, path: datapath.SelectedRelay, instanceID: snapshot.RelayInstanceID}
	default:
		return identity.Verified{}
	}
	return bindings[key]
}

func identityStatus(local, peer identity.Verified) *planeIdentityStatus {
	status := &planeIdentityStatus{Local: sanitizedCertificateStatus(local), Peer: sanitizedCertificateStatus(peer)}
	if status.Local == nil && status.Peer == nil {
		return nil
	}
	return status
}

func selectedDataIdentityStatus(local, peer identity.Verified, path edgePathStatus) *dataIdentityStatus {
	selected := path.Selected
	epoch := uint64(0)
	if selected == string(datapath.SelectedDirect) {
		epoch = path.DirectEpoch
	} else if selected != string(datapath.SelectedRelay) {
		selected = string(datapath.SelectedNone)
	}
	status := &dataIdentityStatus{
		Local: sanitizedCertificateStatus(local), Peer: sanitizedCertificateStatus(peer),
		Path: selected, DirectEpoch: epoch,
	}
	if status.Local == nil && status.Peer == nil {
		return nil
	}
	return status
}

func sanitizedCertificateStatus(verified identity.Verified) *certificateStatus {
	slot := identity.PinSlotName(verified.PinSlot)
	if verified.NotAfter.IsZero() || (slot != "current" && slot != "next") {
		return nil
	}
	return &certificateStatus{Expires: verified.NotAfter.UTC().Format(time.RFC3339), PinSlot: slot}
}
