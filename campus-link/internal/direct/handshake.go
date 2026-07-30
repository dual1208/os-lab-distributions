// Package direct authenticates and validates a direct edge-to-edge QUIC path.
package direct

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/rendezvous"
)

const (
	wireMagic = "CLDIR1\x00\x00"
	wireSize  = 144

	typeHello            = 1
	typeAck              = 2
	typePing             = 3
	typePong             = 4
	typeCommit           = 5
	typeCommitted        = 6
	typeActivate         = 7
	typeActiveAck        = 8
	typeActivated        = 9
	typeCommittedActive  = 10
	typeDeliveryProgress = 11
	typeHealthPing       = 12
	typeHealthPong       = 13

	nonceSize = 16
	macSize   = sha256.Size
)

var ErrAuthentication = errors.New("direct path authentication failed")

const exporterLabel = "EXPORTER-campus-link-direct/1"

// Stream is the bounded reliable 1-RTT stream used only to authenticate and
// stabilize a direct QUIC connection before packet traffic can select it.
type Stream interface {
	io.Reader
	io.Writer
	io.Closer
	SetDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type Options struct {
	Timeout           time.Duration
	StabilityDuration time.Duration
	ProbeInterval     time.Duration
}

type Result struct {
	PathEpoch  uint64
	Validated  time.Time
	ProbeCount uint32

	bound      BoundPlan
	localNonce [nonceSize]byte
	peerNonce  [nonceSize]byte
	context    [sha256.Size]byte
}

// Activation prepares a receive path before it can be selected. Implementors
// must make PrepareDirect receive-only and keep the prior path selected until
// SelectDirect succeeds.
type Activation interface {
	PrepareDirect(uint64) error
	SelectDirect(uint64) error
	CommitDirect(uint64) error
	AbortDirect(uint64)
}

// BoundPlan is intentionally opaque outside this package. A production
// handshake cannot be started with the broker-visible rendezvous.Plan; callers
// must first bind it to an exactly verified end-to-end TLS 1.3 connection.
type BoundPlan struct {
	plan rendezvous.Plan
}

// BindTLSExporter replaces the broker-visible plan key with a key bound to
// this exact end-to-end QUIC/TLS session. The relay knows ProbeKey but cannot
// compute the TLS exporter because it has neither edge private key.
func BindTLSExporter(plan rendezvous.Plan, site string, state tls.ConnectionState, requirements identity.Requirements) (BoundPlan, identity.Verified, error) {
	contextHash, err := planContext(plan, site)
	if err != nil || !state.HandshakeComplete || state.Version != tls.VersionTLS13 {
		return BoundPlan{}, identity.Verified{}, ErrAuthentication
	}
	verified, err := identity.VerifyConnection(state, requirements)
	if err != nil {
		return BoundPlan{}, identity.Verified{}, ErrAuthentication
	}
	exporter, err := state.ExportKeyingMaterial(exporterLabel, contextHash[:], sha256.Size)
	if err != nil || len(exporter) != sha256.Size {
		return BoundPlan{}, identity.Verified{}, ErrAuthentication
	}
	bound, err := bindExporter(plan, site, exporter)
	for index := range exporter {
		exporter[index] = 0
	}
	return bound, verified, err
}

func bindExporter(plan rendezvous.Plan, site string, exporter []byte) (BoundPlan, error) {
	contextHash, err := planContext(plan, site)
	if err != nil || len(exporter) != sha256.Size || plan.ProbeKey == ([32]byte{}) {
		return BoundPlan{}, ErrAuthentication
	}
	mac := hmac.New(sha256.New, plan.ProbeKey[:])
	mac.Write([]byte(exporterLabel))
	mac.Write(contextHash[:])
	mac.Write(exporter)
	derived := mac.Sum(nil)
	copy(plan.ProbeKey[:], derived)
	if plan.ProbeKey == ([32]byte{}) {
		return BoundPlan{}, ErrAuthentication
	}
	return BoundPlan{plan: plan}, nil
}

type frame struct {
	typeCode  byte
	siteCode  byte
	roleCode  byte
	epoch     uint64
	sequence  uint32
	progress  uint64
	nonce     [nonceSize]byte
	peerNonce [nonceSize]byte
	context   [sha256.Size]byte
}

func defaultOptions(options Options) (Options, error) {
	if options.Timeout == 0 {
		options.Timeout = 15 * time.Second
	}
	if options.StabilityDuration == 0 {
		options.StabilityDuration = 5 * time.Second
	}
	if options.ProbeInterval == 0 {
		options.ProbeInterval = 250 * time.Millisecond
	}
	if options.Timeout <= 0 || options.Timeout > time.Minute || options.StabilityDuration <= 0 ||
		options.StabilityDuration > 30*time.Second || options.ProbeInterval <= 0 ||
		options.ProbeInterval > time.Second || options.StabilityDuration < options.ProbeInterval ||
		options.Timeout <= options.StabilityDuration {
		return Options{}, ErrAuthentication
	}
	return options, nil
}

// Initiate authenticates a direct connection from the deterministic site-a
// QUIC client. random must be cryptographically secure in production.
func Initiate(ctx context.Context, stream Stream, bound BoundPlan, site string, random io.Reader, options Options) (Result, error) {
	plan := bound.plan
	if stream == nil || site != "site-a" || plan.Role != rendezvous.RoleSender {
		return Result{}, ErrAuthentication
	}
	result, err := runInitiator(ctx, stream, plan, site, random, options)
	if err == nil {
		result.bound = bound
	}
	return result, err
}

// Accept authenticates a direct connection at the deterministic site-b QUIC
// server. It returns only after the complete bidirectional stability exchange.
func Accept(ctx context.Context, stream Stream, bound BoundPlan, site string, random io.Reader, options Options) (Result, error) {
	plan := bound.plan
	if stream == nil || site != "site-b" || plan.Role != rendezvous.RoleReceiver {
		return Result{}, ErrAuthentication
	}
	result, err := runReceiver(ctx, stream, plan, site, random, options)
	if err == nil {
		result.bound = bound
	}
	return result, err
}

// ActivateInitiator performs the client side of the authenticated cutover
// barrier. Both peers prepare their receive path before the initiator selects
// and announces that selection.
func ActivateInitiator(ctx context.Context, stream Stream, result Result, activation Activation) error {
	return activate(ctx, stream, result, "site-a", true, activation)
}

// ActivateReceiver performs the server side of the authenticated cutover
// barrier. It selects only after receiving the initiator's final ACTIVATED.
func ActivateReceiver(ctx context.Context, stream Stream, result Result, activation Activation) error {
	return activate(ctx, stream, result, "site-b", false, activation)
}

func activate(ctx context.Context, stream Stream, result Result, site string, initiator bool, activation Activation) (err error) {
	plan := result.bound.plan
	if ctx == nil || stream == nil || activation == nil || result.Validated.IsZero() ||
		result.PathEpoch == 0 || result.PathEpoch != plan.PathEpoch || result.context == ([sha256.Size]byte{}) {
		return ErrAuthentication
	}
	wantRole := rendezvous.RoleReceiver
	if initiator {
		wantRole = rendezvous.RoleSender
	}
	if (initiator && site != "site-a") || (!initiator && site != "site-b") || plan.Role != wantRole {
		return ErrAuthentication
	}
	deadline := time.Now().Add(5 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if plan.Expires.Before(deadline) {
		deadline = plan.Expires
	}
	if !deadline.After(time.Now()) || stream.SetDeadline(deadline) != nil {
		return ErrAuthentication
	}
	if err := activation.PrepareDirect(plan.PathEpoch); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			activation.AbortDirect(plan.PathEpoch)
		}
	}()
	localSite, peerSite := byte(2), byte(1)
	localRole, peerRole := rendezvous.RoleReceiver, rendezvous.RoleSender
	if initiator {
		localSite, peerSite = 1, 2
		localRole, peerRole = rendezvous.RoleSender, rendezvous.RoleReceiver
	}
	localFrame := func(kind byte) frame {
		return frame{typeCode: kind, siteCode: localSite, roleCode: byte(localRole), epoch: plan.PathEpoch,
			sequence: result.ProbeCount, nonce: result.localNonce, peerNonce: result.peerNonce, context: result.context}
	}
	matchPeer := func(value frame, kind byte) bool {
		return matches(value, kind, peerSite, peerRole, plan.PathEpoch, result.ProbeCount, result.context) &&
			subtle.ConstantTimeCompare(value.nonce[:], result.peerNonce[:]) == 1 &&
			subtle.ConstantTimeCompare(value.peerNonce[:], result.localNonce[:]) == 1
	}
	if initiator {
		if err := writeFrame(stream, localFrame(typeActivate), plan.ProbeKey[:]); err != nil {
			return fmt.Errorf("direct activation request: %w", err)
		}
		ack, readErr := readFrame(stream, plan.ProbeKey[:])
		if readErr != nil || !matchPeer(ack, typeActiveAck) {
			return ErrAuthentication
		}
		if err := activation.SelectDirect(plan.PathEpoch); err != nil {
			return err
		}
		if err := writeFrame(stream, localFrame(typeActivated), plan.ProbeKey[:]); err != nil {
			return fmt.Errorf("direct activation completion: %w", err)
		}
		confirmed, readErr := readFrame(stream, plan.ProbeKey[:])
		if readErr != nil || !matchPeer(confirmed, typeCommittedActive) {
			return ErrAuthentication
		}
	} else {
		request, readErr := readFrame(stream, plan.ProbeKey[:])
		if readErr != nil || !matchPeer(request, typeActivate) {
			return ErrAuthentication
		}
		if err := writeFrame(stream, localFrame(typeActiveAck), plan.ProbeKey[:]); err != nil {
			return fmt.Errorf("direct activation acknowledgement: %w", err)
		}
		complete, readErr := readFrame(stream, plan.ProbeKey[:])
		if readErr != nil || !matchPeer(complete, typeActivated) {
			return ErrAuthentication
		}
		if err := activation.SelectDirect(plan.PathEpoch); err != nil {
			return err
		}
		if err := writeFrame(stream, localFrame(typeCommittedActive), plan.ProbeKey[:]); err != nil {
			return fmt.Errorf("direct activation selected acknowledgement: %w", err)
		}
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		return err
	}
	if err := activation.CommitDirect(plan.PathEpoch); err != nil {
		return err
	}
	committed = true
	return nil
}

func runInitiator(ctx context.Context, stream Stream, plan rendezvous.Plan, site string, random io.Reader, options Options) (Result, error) {
	options, contextHash, probeCount, err := prepare(ctx, stream, plan, site, options)
	if err != nil {
		return Result{}, err
	}
	if random == nil {
		random = rand.Reader
	}
	var localNonce [nonceSize]byte
	if _, err := io.ReadFull(random, localNonce[:]); err != nil || localNonce == ([nonceSize]byte{}) {
		return Result{}, ErrAuthentication
	}
	if err := writeFrame(stream, frame{typeCode: typeHello, siteCode: 1, roleCode: byte(rendezvous.RoleSender), epoch: plan.PathEpoch, nonce: localNonce, context: contextHash}, plan.ProbeKey[:]); err != nil {
		return Result{}, fmt.Errorf("direct hello: %w", err)
	}
	ack, err := readFrame(stream, plan.ProbeKey[:])
	if err != nil || !matches(ack, typeAck, 2, rendezvous.RoleReceiver, plan.PathEpoch, 0, contextHash) ||
		ack.nonce == ([nonceSize]byte{}) || subtle.ConstantTimeCompare(ack.peerNonce[:], localNonce[:]) != 1 {
		return Result{}, ErrAuthentication
	}
	started := time.Now()
	for sequence := uint32(1); sequence <= probeCount; sequence++ {
		if err := waitProbe(ctx, started, sequence, options.ProbeInterval); err != nil {
			return Result{}, err
		}
		ping := frame{typeCode: typePing, siteCode: 1, roleCode: byte(rendezvous.RoleSender), epoch: plan.PathEpoch,
			sequence: sequence, nonce: localNonce, peerNonce: ack.nonce, context: contextHash}
		if err := writeFrame(stream, ping, plan.ProbeKey[:]); err != nil {
			return Result{}, fmt.Errorf("direct stability ping: %w", err)
		}
		pong, err := readFrame(stream, plan.ProbeKey[:])
		if err != nil || !matches(pong, typePong, 2, rendezvous.RoleReceiver, plan.PathEpoch, sequence, contextHash) ||
			subtle.ConstantTimeCompare(pong.nonce[:], ack.nonce[:]) != 1 ||
			subtle.ConstantTimeCompare(pong.peerNonce[:], localNonce[:]) != 1 {
			return Result{}, ErrAuthentication
		}
	}
	commit := frame{typeCode: typeCommit, siteCode: 1, roleCode: byte(rendezvous.RoleSender), epoch: plan.PathEpoch,
		sequence: probeCount, nonce: localNonce, peerNonce: ack.nonce, context: contextHash}
	if err := writeFrame(stream, commit, plan.ProbeKey[:]); err != nil {
		return Result{}, fmt.Errorf("direct commit: %w", err)
	}
	committed, err := readFrame(stream, plan.ProbeKey[:])
	if err != nil || !matches(committed, typeCommitted, 2, rendezvous.RoleReceiver, plan.PathEpoch, probeCount, contextHash) ||
		subtle.ConstantTimeCompare(committed.nonce[:], ack.nonce[:]) != 1 ||
		subtle.ConstantTimeCompare(committed.peerNonce[:], localNonce[:]) != 1 {
		return Result{}, ErrAuthentication
	}
	validated := time.Now()
	if validated.Sub(started) < options.StabilityDuration {
		return Result{}, ErrAuthentication
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		return Result{}, err
	}
	return Result{PathEpoch: plan.PathEpoch, Validated: validated, ProbeCount: probeCount,
		localNonce: localNonce, peerNonce: ack.nonce, context: contextHash}, nil
}

func runReceiver(ctx context.Context, stream Stream, plan rendezvous.Plan, site string, random io.Reader, options Options) (Result, error) {
	options, contextHash, probeCount, err := prepare(ctx, stream, plan, site, options)
	if err != nil {
		return Result{}, err
	}
	if random == nil {
		random = rand.Reader
	}
	hello, err := readFrame(stream, plan.ProbeKey[:])
	if err != nil || !matches(hello, typeHello, 1, rendezvous.RoleSender, plan.PathEpoch, 0, contextHash) || hello.nonce == ([nonceSize]byte{}) {
		return Result{}, ErrAuthentication
	}
	var localNonce [nonceSize]byte
	if _, err := io.ReadFull(random, localNonce[:]); err != nil || localNonce == ([nonceSize]byte{}) {
		return Result{}, ErrAuthentication
	}
	ack := frame{typeCode: typeAck, siteCode: 2, roleCode: byte(rendezvous.RoleReceiver), epoch: plan.PathEpoch,
		nonce: localNonce, peerNonce: hello.nonce, context: contextHash}
	if err := writeFrame(stream, ack, plan.ProbeKey[:]); err != nil {
		return Result{}, fmt.Errorf("direct acknowledgement: %w", err)
	}
	started := time.Now()
	for sequence := uint32(1); sequence <= probeCount; sequence++ {
		ping, err := readFrame(stream, plan.ProbeKey[:])
		if err != nil || !matches(ping, typePing, 1, rendezvous.RoleSender, plan.PathEpoch, sequence, contextHash) ||
			subtle.ConstantTimeCompare(ping.nonce[:], hello.nonce[:]) != 1 ||
			subtle.ConstantTimeCompare(ping.peerNonce[:], localNonce[:]) != 1 {
			return Result{}, ErrAuthentication
		}
		pong := frame{typeCode: typePong, siteCode: 2, roleCode: byte(rendezvous.RoleReceiver), epoch: plan.PathEpoch,
			sequence: sequence, nonce: localNonce, peerNonce: hello.nonce, context: contextHash}
		if err := writeFrame(stream, pong, plan.ProbeKey[:]); err != nil {
			return Result{}, fmt.Errorf("direct stability pong: %w", err)
		}
	}
	commit, err := readFrame(stream, plan.ProbeKey[:])
	if err != nil || !matches(commit, typeCommit, 1, rendezvous.RoleSender, plan.PathEpoch, probeCount, contextHash) ||
		subtle.ConstantTimeCompare(commit.nonce[:], hello.nonce[:]) != 1 ||
		subtle.ConstantTimeCompare(commit.peerNonce[:], localNonce[:]) != 1 || time.Since(started) < options.StabilityDuration {
		return Result{}, ErrAuthentication
	}
	committed := frame{typeCode: typeCommitted, siteCode: 2, roleCode: byte(rendezvous.RoleReceiver), epoch: plan.PathEpoch,
		sequence: probeCount, nonce: localNonce, peerNonce: hello.nonce, context: contextHash}
	if err := writeFrame(stream, committed, plan.ProbeKey[:]); err != nil {
		return Result{}, fmt.Errorf("direct committed acknowledgement: %w", err)
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		return Result{}, err
	}
	return Result{PathEpoch: plan.PathEpoch, Validated: time.Now(), ProbeCount: probeCount,
		localNonce: localNonce, peerNonce: hello.nonce, context: contextHash}, nil
}

func prepare(ctx context.Context, stream Stream, plan rendezvous.Plan, site string, options Options) (Options, [sha256.Size]byte, uint32, error) {
	var zero [sha256.Size]byte
	if ctx == nil || plan.Circuit == "" || plan.Generation == "" || plan.PeerGeneration == "" ||
		!control.ValidSourceVersion(plan.Version) || !control.ValidDeploymentID(plan.DeploymentID) || !control.ValidRelayGeneration(plan.RelayGeneration) ||
		plan.Generation == plan.PeerGeneration || plan.PathEpoch == 0 || plan.Attempt == 0 ||
		plan.Session == ([16]byte{}) || plan.ProbeKey == ([32]byte{}) || !plan.Expires.After(time.Now()) {
		return Options{}, zero, 0, ErrAuthentication
	}
	options, err := defaultOptions(options)
	if err != nil {
		return Options{}, zero, 0, err
	}
	deadline := time.Now().Add(options.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if plan.Expires.Before(deadline) {
		deadline = plan.Expires
	}
	if time.Until(deadline) <= options.StabilityDuration {
		return Options{}, zero, 0, ErrAuthentication
	}
	if err := stream.SetDeadline(deadline); err != nil {
		return Options{}, zero, 0, err
	}
	contextHash, err := planContext(plan, site)
	if err != nil {
		return Options{}, zero, 0, err
	}
	probeCount := uint32((options.StabilityDuration + options.ProbeInterval - 1) / options.ProbeInterval)
	if probeCount == 0 || probeCount > 120 {
		return Options{}, zero, 0, ErrAuthentication
	}
	return options, contextHash, probeCount, nil
}

func planContext(plan rendezvous.Plan, site string) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	var generationA, generationB string
	switch site {
	case "site-a":
		generationA, generationB = plan.Generation, plan.PeerGeneration
	case "site-b":
		generationA, generationB = plan.PeerGeneration, plan.Generation
	default:
		return zero, ErrAuthentication
	}
	h := sha256.New()
	for _, value := range []string{"campus-link/direct/1", plan.Circuit, plan.Version, plan.DeploymentID, plan.RelayGeneration, generationA, generationB} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		h.Write(length[:])
		h.Write([]byte(value))
	}
	h.Write(plan.Session[:])
	var numeric [12]byte
	binary.BigEndian.PutUint64(numeric[:8], plan.PathEpoch)
	binary.BigEndian.PutUint32(numeric[8:], plan.Attempt)
	h.Write(numeric[:])
	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

func matches(candidate frame, typeCode, siteCode byte, role rendezvous.Role, epoch uint64, sequence uint32, contextHash [sha256.Size]byte) bool {
	return candidate.typeCode == typeCode && candidate.siteCode == siteCode && candidate.roleCode == byte(role) &&
		candidate.epoch == epoch && candidate.sequence == sequence &&
		subtle.ConstantTimeCompare(candidate.context[:], contextHash[:]) == 1
}

func waitProbe(ctx context.Context, started time.Time, sequence uint32, interval time.Duration) error {
	target := started.Add(time.Duration(sequence) * interval)
	timer := time.NewTimer(time.Until(target))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func writeFrame(writer io.Writer, value frame, key []byte) error {
	packet := make([]byte, wireSize)
	copy(packet[:8], wireMagic)
	packet[8], packet[9], packet[10] = value.typeCode, value.siteCode, value.roleCode
	binary.BigEndian.PutUint64(packet[12:20], value.epoch)
	binary.BigEndian.PutUint32(packet[20:24], value.sequence)
	copy(packet[24:40], value.nonce[:])
	copy(packet[40:56], value.peerNonce[:])
	copy(packet[56:88], value.context[:])
	binary.BigEndian.PutUint64(packet[88:96], value.progress)
	mac := hmac.New(sha256.New, key)
	mac.Write(packet[:wireSize-macSize])
	copy(packet[wireSize-macSize:], mac.Sum(nil))
	for len(packet) != 0 {
		written, err := writer.Write(packet)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(packet) {
			return io.ErrShortWrite
		}
		packet = packet[written:]
	}
	return nil
}

func readFrame(reader io.Reader, key []byte) (frame, error) {
	var value frame
	packet := make([]byte, wireSize)
	if _, err := io.ReadFull(reader, packet); err != nil {
		return value, err
	}
	if string(packet[:8]) != wireMagic || packet[11] != 0 || subtle.ConstantTimeByteEq(packet[8], 0) == 1 ||
		packet[8] > typeHealthPong || (packet[9] != 1 && packet[9] != 2) ||
		(packet[10] != byte(rendezvous.RoleSender) && packet[10] != byte(rendezvous.RoleReceiver)) ||
		!allZero(packet[96:wireSize-macSize]) {
		return value, ErrAuthentication
	}
	typeCode := packet[8]
	sequence := binary.BigEndian.Uint32(packet[20:24])
	progress := binary.BigEndian.Uint64(packet[88:96])
	if (typeCode <= typeCommittedActive && progress != 0) ||
		(typeCode == typeDeliveryProgress && (sequence != 0 || progress == 0)) ||
		((typeCode == typeHealthPing || typeCode == typeHealthPong) && sequence == 0) {
		return value, ErrAuthentication
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(packet[:wireSize-macSize])
	if !hmac.Equal(packet[wireSize-macSize:], mac.Sum(nil)) {
		return value, ErrAuthentication
	}
	value.typeCode, value.siteCode, value.roleCode = packet[8], packet[9], packet[10]
	value.epoch = binary.BigEndian.Uint64(packet[12:20])
	value.sequence = sequence
	value.progress = progress
	copy(value.nonce[:], packet[24:40])
	copy(value.peerNonce[:], packet[40:56])
	copy(value.context[:], packet[56:88])
	return value, nil
}

func allZero(buffer []byte) bool {
	var combined byte
	for _, value := range buffer {
		combined |= value
	}
	return subtle.ConstantTimeByteEq(combined, 0) == 1
}
