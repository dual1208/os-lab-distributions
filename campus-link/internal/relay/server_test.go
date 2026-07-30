package relay

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/binding"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/rendezvous"
)

const relayZeroSPKIPin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
const relayOneSPKIPin = "sha256/AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
const relayTwoSPKIPin = "sha256/AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
const relayTestVersion = "test-v1"
const relayTestDeploymentID = "0123456789abcdef0123456789abcdef"

func newTestRelay(cfg config.Relay, version string) (*Server, error) {
	anchor := rendezvous.BootAnchorSourceFunc(func() ([32]byte, error) {
		var digest [32]byte
		for index := range digest {
			digest[index] = 0xa1
		}
		return digest, nil
	})
	return newServer(cfg, version, true, anchor)
}

func validRelayConfig(t *testing.T) config.Relay {
	t.Helper()
	return config.Relay{
		Circuit: "c", DeploymentID: relayTestDeploymentID,
		EpochStatePath: filepath.Join(t.TempDir(), "epochs.json"),
		Prefixes:       map[string]string{"site-a": "10.81.0.0/24", "site-b": "10.82.0.0/24"},
		LocalControlIdentity: config.IdentityAuthorization{
			URI: "spiffe://campus-link/c/relay/control", CurrentSPKI: relayTwoSPKIPin,
		},
		ControlIdentities: map[string]config.IdentityAuthorization{
			"site-a": {URI: "spiffe://campus-link/c/site-a/control", CurrentSPKI: relayZeroSPKIPin},
			"site-b": {URI: "spiffe://campus-link/c/site-b/control", CurrentSPKI: relayOneSPKIPin},
		},
	}
}

func TestNewRejectsIdentityPinReuseAcrossSites(t *testing.T) {
	cfg := validRelayConfig(t)
	siteB := cfg.ControlIdentities["site-b"]
	siteB.CurrentSPKI = cfg.ControlIdentities["site-a"].CurrentSPKI
	cfg.ControlIdentities["site-b"] = siteB
	if _, err := New(cfg, relayTestVersion); err == nil {
		t.Fatal("same current SPKI authorized for both sites")
	}

	cfg = validRelayConfig(t)
	siteB = cfg.ControlIdentities["site-b"]
	siteB.NextSPKI = cfg.ControlIdentities["site-a"].CurrentSPKI
	cfg.ControlIdentities["site-b"] = siteB
	if _, err := New(cfg, relayTestVersion); err == nil {
		t.Fatal("site-a current SPKI reused as site-b next SPKI")
	}
}

func TestNewRejectsMissingOrNonCanonicalEpochNamespace(t *testing.T) {
	tests := []struct {
		name    string
		version string
		mutate  func(*config.Relay)
	}{
		{"missing version", "", func(*config.Relay) {}},
		{"missing deployment", relayTestVersion, func(cfg *config.Relay) { cfg.DeploymentID = "" }},
		{"uppercase deployment", relayTestVersion, func(cfg *config.Relay) { cfg.DeploymentID = "ABCDEF0123456789ABCDEF0123456789" }},
		{"relative state path", relayTestVersion, func(cfg *config.Relay) { cfg.EpochStatePath = "epochs.json" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validRelayConfig(t)
			test.mutate(&cfg)
			if _, err := New(cfg, test.version); err == nil {
				t.Fatal("invalid relay epoch namespace accepted")
			}
		})
	}
}

func TestPreflightConstructorDoesNotCreateRuntimeEpochAuthority(t *testing.T) {
	cfg := validRelayConfig(t)
	server, err := NewForPreflight(cfg, relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(cfg.EpochStatePath); !os.IsNotExist(err) {
		t.Fatalf("preflight mutated runtime epoch state: %v", err)
	}
	if server.planner != nil || server.relayGeneration != "" {
		t.Fatal("preflight constructor retained runtime epoch authority")
	}
	if err := server.Run(context.Background()); err == nil {
		t.Fatal("preflight-only server was allowed to start listeners")
	}
}

func TestLatestControlSessionExclusivelyOwnsLeg(t *testing.T) {
	s, err := newTestRelay(validRelayConfig(t), relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	oldClient, oldServer := net.Pipe()
	defer oldClient.Close()
	defer oldServer.Close()
	newClient, newServer := net.Pipe()
	defer newClient.Close()
	defer newServer.Close()
	oldOwner, err := s.activateLegLocked("site-a", "same-generation", relayBindingToken(0x10), oldServer)
	if err != nil {
		t.Fatal(err)
	}
	newOwner, err := s.activateLegLocked("site-a", "same-generation", relayBindingToken(0x20), newServer)
	if err != nil {
		t.Fatal(err)
	}
	if s.clearLegLocked("site-a", oldOwner) {
		t.Fatal("stale handler cleared the replacement session")
	}
	if !s.legs["site-a"].online || s.legs["site-a"].owner != newOwner {
		t.Fatal("replacement session lost ownership")
	}
	if !s.clearLegLocked("site-a", newOwner) || s.legs["site-a"].online {
		t.Fatal("current handler did not clear its session")
	}
	s.mu.Unlock()
}

func TestEstablishedCircuitInvalidatesBothLegsTogether(t *testing.T) {
	s, err := newTestRelay(validRelayConfig(t), relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	aClient, aServer := net.Pipe()
	defer aClient.Close()
	defer aServer.Close()
	bClient, bServer := net.Pipe()
	defer bClient.Close()
	defer bServer.Close()
	s.mu.Lock()
	aOwner, err := s.activateLegLocked("site-a", "g", relayBindingToken(0x30), aServer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.activateLegLocked("site-b", "g", relayBindingToken(0x40), bServer); err != nil {
		t.Fatal(err)
	}
	if !s.established {
		t.Fatal("two authenticated legs did not establish the circuit")
	}
	if !s.clearLegLocked("site-a", aOwner) {
		t.Fatal("current site owner was not cleared")
	}
	if s.legs["site-a"].online || s.legs["site-b"].online || s.established {
		t.Fatal("peer leg survived an established circuit member loss")
	}
	s.mu.Unlock()
}

func TestOuterDatagramLimitIsBounded(t *testing.T) {
	if maxOuterDatagramSize < 1280 || maxOuterDatagramSize > 4096 {
		t.Fatalf("unexpected outer datagram limit: %d", maxOuterDatagramSize)
	}
}

func TestControlAdmissionAndHeartbeatValidationAreBounded(t *testing.T) {
	s, err := newTestRelay(validRelayConfig(t), relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	addresses := make([]net.Addr, 0, maxPreauthConnections)
	for i := 0; i < maxPreauthConnections; i++ {
		address := &net.TCPAddr{IP: net.IPv4(192, 0, 2, byte(i+1)), Port: 40000 + i}
		addresses = append(addresses, address)
		if !s.acquireControlSlot(address) {
			t.Fatalf("slot %d rejected before bound", i)
		}
	}
	if s.acquireControlSlot(&net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 41000}) {
		t.Fatal("control admission exceeded hard connection bound")
	}
	for _, address := range addresses {
		s.releaseControlSlot(address)
	}
	sharedSource := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 42000}
	if !s.acquireControlSlot(sharedSource) || !s.acquireControlSlot(sharedSource) {
		t.Fatal("per-source capacity rejected before its bound")
	}
	if s.acquireControlSlot(sharedSource) {
		t.Fatal("one source consumed more than its pre-authentication bound")
	}
	s.releaseControlSlot(sharedSource)
	s.releaseControlSlot(sharedSource)
	if !s.acquireControlSlot(sharedSource) {
		t.Fatal("released control capacity was not reusable")
	}
	s.releaseControlSlot(sharedSource)

	now := time.Unix(1_800_000_000, 0)
	heartbeat := func(sequence uint64) control.Heartbeat {
		return control.Heartbeat{
			Type: "heartbeat", Sequence: sequence, EdgeWallUnixNano: now.UnixNano(), EdgeMonotonicNano: sequence,
		}
	}
	if !validHeartbeat(heartbeat(1), 0, time.Time{}, now) {
		t.Fatal("first valid heartbeat rejected")
	}
	if validHeartbeat(heartbeat(1), 1, now.Add(-2*time.Second), now) {
		t.Fatal("replayed heartbeat sequence accepted")
	}
	if validHeartbeat(heartbeat(2), 1, now.Add(-500*time.Millisecond), now) {
		t.Fatal("heartbeat amplification rate accepted")
	}
	if !validHeartbeat(heartbeat(2), 1, now.Add(-time.Second), now) {
		t.Fatal("monotonic rate-compliant heartbeat rejected")
	}
	invalid := heartbeat(3)
	invalid.EdgeWallUnixNano = 0
	if validHeartbeat(invalid, 2, now.Add(-time.Second), now) {
		t.Fatal("legacy heartbeat without clock fields accepted")
	}
}

func TestRelayClockAcknowledgementEchoesOnlyAuthenticatedSample(t *testing.T) {
	received := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	heartbeat := control.Heartbeat{
		Type: "heartbeat", Sequence: 9, EdgeWallUnixNano: received.Add(-20 * time.Millisecond).UnixNano(), EdgeMonotonicNano: 77,
	}
	ack, ok := relayClockAcknowledgement(heartbeat, received, received.Add(3*time.Millisecond))
	if !ok {
		t.Fatal("canonical relay clock acknowledgement rejected")
	}
	if ack.Sequence != heartbeat.Sequence || ack.EdgeMonotonicNano != heartbeat.EdgeMonotonicNano ||
		ack.RelayReceiveUnixNano != received.UnixNano() || ack.RelaySendUnixNano != received.Add(3*time.Millisecond).UnixNano() {
		t.Fatalf("relay acknowledgement did not bind exact clock samples: %#v", ack)
	}
	if _, ok := relayClockAcknowledgementCaptured(
		heartbeat, received, received.Add(time.Millisecond), received.UnixNano(), received.UnixNano()-1,
	); ok {
		t.Fatal("relay wall rollback produced an acknowledgement")
	}
	if _, ok := relayClockAcknowledgementCaptured(
		heartbeat, received, received.Add(time.Millisecond), received.UnixNano(), received.Add(100*time.Millisecond).UnixNano(),
	); ok {
		t.Fatal("relay wall step diverging from monotonic time produced an acknowledgement")
	}
	if _, ok := relayClockAcknowledgement(heartbeat, received, received.Add(time.Second+time.Nanosecond)); ok {
		t.Fatal("unbounded relay processing produced an acknowledgement")
	}
	legacy := heartbeat
	legacy.EdgeMonotonicNano = 0
	if _, ok := relayClockAcknowledgement(legacy, received, received); ok {
		t.Fatal("legacy heartbeat produced a clock acknowledgement")
	}
}

func TestRegistrationRequiresExactAuthenticatedSourceNamespace(t *testing.T) {
	s, err := newTestRelay(validRelayConfig(t), relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	valid := control.Register{
		Type: "register", Site: "site-a", Generation: "ga", Version: relayTestVersion,
		DeploymentID: relayTestDeploymentID, Circuit: "c", Prefix: "10.81.0.0/24",
		Transports: []string{"quic-datagram"},
	}
	if !s.validRegistration(valid, "site-a") {
		t.Fatal("exact authenticated registration rejected")
	}
	response := s.registeredResponse(relayBindingToken(0x12))
	if response.Type != "registered" || response.Version != relayTestVersion ||
		response.DeploymentID != relayTestDeploymentID || response.RelayGeneration != s.relayGeneration ||
		!control.ValidRelayGeneration(response.RelayGeneration) {
		t.Fatalf("Registered did not authenticate the exact relay namespace: %#v", response)
	}
	tests := []struct {
		name   string
		mutate func(*control.Register)
	}{
		{"wrong source version", func(reg *control.Register) { reg.Version = "other" }},
		{"empty source version", func(reg *control.Register) { reg.Version = "" }},
		{"wrong deployment", func(reg *control.Register) { reg.DeploymentID = "ffffffffffffffffffffffffffffffff" }},
		{"uppercase deployment", func(reg *control.Register) { reg.DeploymentID = "ABCDEF0123456789ABCDEF0123456789" }},
		{"claimed site mismatch", func(reg *control.Register) { reg.Site = "site-b" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if s.validRegistration(candidate, "site-a") {
				t.Fatal("mismatched registration accepted")
			}
		})
	}
}

func TestRelayPlannerEpochAndGenerationSurviveServerRestart(t *testing.T) {
	cfg := validRelayConfig(t)
	firstServer, err := newTestRelay(cfg, relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	firstGeneration := firstServer.relayGeneration
	now := time.Unix(1_800_000_000, 0)
	firstServer.planner.Register("site-a", "ga", 1)
	firstServer.planner.Register("site-b", "gb", 2)
	firstServer.planner.Observe("site-a", 1, netip.MustParseAddrPort("198.51.100.1:40001"), now)
	firstServer.planner.Observe("site-b", 2, netip.MustParseAddrPort("203.0.113.2:40002"), now)
	firstPlan, ok := firstServer.planner.PlanForAt("site-a", 1, now)
	if !ok {
		t.Fatal("first server did not create a plan")
	}

	restarted, err := newTestRelay(cfg, relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.relayGeneration != firstGeneration {
		t.Fatal("ordinary relay restart changed authority generation")
	}
	restarted.planner.Register("site-a", "ga", 1)
	restarted.planner.Register("site-b", "gb", 2)
	restarted.planner.Observe("site-a", 1, netip.MustParseAddrPort("198.51.100.1:40001"), now)
	restarted.planner.Observe("site-b", 2, netip.MustParseAddrPort("203.0.113.2:40002"), now)
	secondPlan, ok := restarted.planner.PlanForAt("site-a", 1, now)
	if !ok {
		t.Fatal("restarted server did not create a plan")
	}
	if secondPlan.PathEpoch != firstPlan.PathEpoch+1 || secondPlan.Session == firstPlan.Session || secondPlan.ProbeKey == firstPlan.ProbeKey {
		t.Fatalf("restart reused rendezvous authority: first=%#v second=%#v", firstPlan, secondPlan)
	}
}

func TestRelayControlDeadlinesNeverExceedCertificateCutoff(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cutoff := now.Add(2 * time.Second)
	for _, timeout := range []time.Duration{5 * time.Second, 45 * time.Second} {
		deadline, err := relayControlDeadline(now, timeout, cutoff)
		if err != nil {
			t.Fatal(err)
		}
		if !deadline.Equal(cutoff) {
			t.Fatalf("timeout %s produced deadline %s beyond cutoff %s", timeout, deadline, cutoff)
		}
	}
	if _, err := relayControlDeadline(cutoff, time.Second, cutoff); err == nil {
		t.Fatal("elapsed certificate cutoff accepted")
	}
}

func TestControlConnectionIsClosedAtCertificateCutoff(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	cutoff := time.Now().Add(25 * time.Millisecond)
	guard, err := closeConnectionAtCutoff(server, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Stop()
	readDone := make(chan error, 1)
	go func() {
		var buffer [1]byte
		_, err := client.Read(buffer[:])
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("cutoff close returned a successful read")
		}
		if time.Now().Before(cutoff) {
			t.Fatal("control connection closed before certificate cutoff")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("control connection outlived certificate cutoff")
	}
}

func TestExpiredControlLegLosesRelayAuthorityImmediately(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	if legAuthorizedAt(&leg{online: true, cutoff: now}, now) {
		t.Fatal("expired control leg retained authority")
	}
	if !legAuthorizedAt(&leg{online: true, cutoff: now.Add(time.Nanosecond)}, now) {
		t.Fatal("unexpired control leg lost authority early")
	}
	if !legAuthorizedAt(&leg{online: true}, now) {
		t.Fatal("legacy test leg without a runtime cutoff lost authority")
	}
}

func TestRelayPlannerScopesCandidatesToCurrentOwners(t *testing.T) {
	s, err := newTestRelay(validRelayConfig(t), relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	aClient, aServer := net.Pipe()
	defer aClient.Close()
	defer aServer.Close()
	bClient, bServer := net.Pipe()
	defer bClient.Close()
	defer bServer.Close()
	s.mu.Lock()
	aOwner, err := s.activateLegLocked("site-a", "ga", relayBindingToken(0x50), aServer)
	if err != nil {
		t.Fatal(err)
	}
	bOwner, err := s.activateLegLocked("site-b", "gb", relayBindingToken(0x60), bServer)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Unlock()
	now := time.Unix(1_800_000_000, 0)
	if err := s.planner.Observe("site-a", aOwner, netip.MustParseAddrPort("198.51.100.1:40001"), now); err != nil {
		t.Fatal(err)
	}
	if err := s.planner.Observe("site-b", bOwner, netip.MustParseAddrPort("203.0.113.2:40002"), now); err != nil {
		t.Fatal(err)
	}
	plan, ok := s.planner.PlanFor("site-a", aOwner)
	if !ok || plan.Circuit != "c" || plan.Generation != "ga" || plan.PeerGeneration != "gb" {
		t.Fatalf("invalid relay plan: %#v", plan)
	}

	s.mu.Lock()
	newOwner, err := s.activateLegLocked("site-a", "ga2", relayBindingToken(0x70), aServer)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Unlock()
	if newOwner == aOwner {
		t.Fatal("replacement owner did not advance")
	}
	if _, ok := s.planner.PlanFor("site-b", bOwner); ok {
		t.Fatal("peer retained plan after owner replacement")
	}
}

func TestBindingResponseCannotCompleteOrRebindFromWrongTuple(t *testing.T) {
	s, err := newTestRelay(validRelayConfig(t), relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	s.udp = udp
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	token := relayBindingToken(0x80)
	s.mu.Lock()
	if _, err := s.activateLegLocked("site-a", "ga", token, peer); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()

	tupleA := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41001}
	tupleB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41002}
	request1, _, err := binding.NewRequestWithNonce("site-a", 1, relayBindingNonce(0x11), token)
	if err != nil {
		t.Fatal(err)
	}
	if !relayHandleBinding(t, s, request1, tupleA) {
		t.Fatal("authenticated request was not consumed")
	}
	challenge1 := relayChallengeFromSnapshot(s.legs["site-a"].bindState.Snapshot())
	response1, err := binding.NewResponse(challenge1, token)
	if err != nil {
		t.Fatal(err)
	}

	relayHandleBinding(t, s, response1, tupleB)
	if snapshot := s.legs["site-a"].bindState.Snapshot(); snapshot.Complete || s.legs["site-a"].bound {
		t.Fatalf("wrong tuple completed transaction: snapshot=%#v", snapshot)
	}
	relayHandleBinding(t, s, response1, tupleA)
	if snapshot := s.legs["site-a"].bindState.Snapshot(); !snapshot.Complete || !s.legs["site-a"].bound || !sameAddr(s.legs["site-a"].addr, tupleA) {
		t.Fatalf("retained tuple did not complete: snapshot=%#v addr=%v", snapshot, s.legs["site-a"].addr)
	}

	// Captured request/response flights from another source are harmless once
	// the transaction is complete.
	relayHandleBinding(t, s, request1, tupleB)
	relayHandleBinding(t, s, response1, tupleB)
	if !s.legs["site-a"].bound || !sameAddr(s.legs["site-a"].addr, tupleA) {
		t.Fatalf("completed replay rebound tuple: %v", s.legs["site-a"].addr)
	}

	request2, _, err := binding.NewRequestWithNonce("site-a", 2, relayBindingNonce(0x22), token)
	if err != nil {
		t.Fatal(err)
	}
	relayHandleBinding(t, s, request2, tupleB)
	if !s.legs["site-a"].bound || !sameAddr(s.legs["site-a"].addr, tupleA) || !sameAddr(s.legs["site-a"].pendingAddr, tupleB) {
		t.Fatalf("unproven higher sequence displaced last proven tuple: %#v", s.legs["site-a"])
	}
	challenge2 := relayChallengeFromSnapshot(s.legs["site-a"].bindState.Snapshot())
	response2, err := binding.NewResponse(challenge2, token)
	if err != nil {
		t.Fatal(err)
	}
	relayHandleBinding(t, s, response2, tupleA)
	if !s.legs["site-a"].bound || !sameAddr(s.legs["site-a"].addr, tupleA) {
		t.Fatal("wrong-source response displaced last proven tuple")
	}
	relayHandleBinding(t, s, response2, tupleB)
	if !s.legs["site-a"].bound || !sameAddr(s.legs["site-a"].addr, tupleB) {
		t.Fatalf("higher-sequence transaction did not bind new tuple: %v", s.legs["site-a"].addr)
	}
}

func TestTwoLegBindingRecoversLostReadyWithoutForeignRebind(t *testing.T) {
	s, err := newTestRelay(validRelayConfig(t), relayTestVersion)
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	s.udp = udp
	clientA := relayUDPClient(t)
	defer clientA.Close()
	clientB := relayUDPClient(t)
	defer clientB.Close()
	foreign := relayUDPClient(t)
	defer foreign.Close()
	tokenA, tokenB := relayBindingToken(0x90), relayBindingToken(0xb0)
	aControl, aPeer := net.Pipe()
	defer aControl.Close()
	defer aPeer.Close()
	bControl, bPeer := net.Pipe()
	defer bControl.Close()
	defer bPeer.Close()
	s.mu.Lock()
	if _, err := s.activateLegLocked("site-a", "ga", tokenA, aPeer); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	if _, err := s.activateLegLocked("site-b", "gb", tokenB, bPeer); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()

	requestA, _, err := binding.NewRequestWithNonce("site-a", 1, relayBindingNonce(0x31), tokenA)
	if err != nil {
		t.Fatal(err)
	}
	relayHandleBinding(t, s, requestA, clientA.LocalAddr().(*net.UDPAddr))
	challengePacketA := relayReadUDP(t, clientA)
	challengeA, ok := binding.ParseChallenge(challengePacketA, tokenA)
	if !ok {
		t.Fatal("site-a challenge was not authenticated")
	}
	responseA, err := binding.NewResponse(challengeA, tokenA)
	if err != nil {
		t.Fatal(err)
	}
	relayHandleBinding(t, s, responseA, clientA.LocalAddr().(*net.UDPAddr))
	relayExpectNoUDP(t, clientA)

	requestB, _, err := binding.NewRequestWithNonce("site-b", 1, relayBindingNonce(0x41), tokenB)
	if err != nil {
		t.Fatal(err)
	}
	relayHandleBinding(t, s, requestB, clientB.LocalAddr().(*net.UDPAddr))
	challengePacketB := relayReadUDP(t, clientB)
	challengeB, ok := binding.ParseChallenge(challengePacketB, tokenB)
	if !ok {
		t.Fatal("site-b challenge was not authenticated")
	}
	responseB, err := binding.NewResponse(challengeB, tokenB)
	if err != nil {
		t.Fatal(err)
	}
	relayHandleBinding(t, s, responseB, clientB.LocalAddr().(*net.UDPAddr))
	readyA := relayReadUDP(t, clientA)
	readyB := relayReadUDP(t, clientB)
	readyMetaA, okA := binding.ParseReady(readyA, tokenA)
	readyMetaB, okB := binding.ParseReady(readyB, tokenB)
	if !okA || !readyMetaA.SameTransaction(challengeA) || !okB || !readyMetaB.SameTransaction(challengeB) {
		t.Fatal("READY flights were not token-scoped and transaction-correlated")
	}

	// Treat the first site-a READY as lost. Replaying its exact response from
	// the proven tuple must return a byte-identical READY.
	relayHandleBinding(t, s, responseA, clientA.LocalAddr().(*net.UDPAddr))
	replayedReadyA := relayReadUDP(t, clientA)
	if string(replayedReadyA) != string(readyA) {
		t.Fatal("lost READY recovery was not byte-identical")
	}

	foreignAddr := foreign.LocalAddr().(*net.UDPAddr)
	relayHandleBinding(t, s, requestA, foreignAddr)
	relayHandleBinding(t, s, responseA, foreignAddr)
	relayExpectNoUDP(t, foreign)
	if !sameAddr(s.legs["site-a"].addr, clientA.LocalAddr().(*net.UDPAddr)) {
		t.Fatal("foreign duplicate flight rebound site-a")
	}
}

func relayUDPClient(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func relayHandleBinding(t *testing.T, server *Server, packet []byte, source *net.UDPAddr) bool {
	t.Helper()
	consumed, err := server.handleBinding(packet, source)
	if err != nil {
		t.Fatal(err)
	}
	return consumed
}

func relayReadUDP(t *testing.T, conn *net.UDPConn) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 256)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buf[:n]...)
}

func relayExpectNoUDP(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 256)
	if _, _, err := conn.ReadFromUDP(buf); err == nil {
		t.Fatal("unexpected UDP reply")
	} else if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
		t.Fatal(err)
	}
}

func relayBindingToken(start byte) []byte {
	token := make([]byte, binding.TokenSize)
	for i := range token {
		token[i] = start + byte(i)
	}
	return token
}

func relayBindingNonce(start byte) binding.Nonce {
	var nonce binding.Nonce
	for i := range nonce {
		nonce[i] = start + byte(i)
	}
	return nonce
}

func relayChallengeFromSnapshot(snapshot binding.ServerSnapshot) binding.Metadata {
	return binding.Metadata{
		Type: binding.TypeChallenge, Site: snapshot.Site, Sequence: snapshot.Sequence,
		RequestNonce: snapshot.RequestNonce, Challenge: snapshot.Challenge,
	}
}
