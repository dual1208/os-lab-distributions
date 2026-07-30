package datapath

import (
	"context"
	"errors"
	"testing"
	"time"
)

func newDirectRequiredMux(t *testing.T, timeout time.Duration) (*Mux, *fakeConnection, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	peer, relay := connectionPair()
	mux, err := NewWithOptions(ctx, 1200, relay, Options{
		RequireDirect: true, NoPathRecoveryTimeout: timeout,
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return mux, peer, func() {
		mux.Close()
		cancel()
	}
}

func TestDirectRequiredStartupNeverSendsOrReceivesRelayPayload(t *testing.T) {
	mux, relayPeer, cleanup := newDirectRequiredMux(t, time.Second)
	defer cleanup()
	snapshot := mux.Snapshot()
	if !snapshot.DirectRequired || snapshot.Selected != SelectedNone || !snapshot.RelayHealthy {
		t.Fatalf("direct-required startup selected relay: %#v", snapshot)
	}
	sendCtx, cancelSend := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelSend()
	if err := mux.SendPacketContext(sendCtx, []byte{0x45}); !errors.Is(err, ErrNoHealthyPath) {
		t.Fatalf("startup send returned %v", err)
	}
	select {
	case wire := <-relayPeer.inbound:
		t.Fatalf("startup payload traversed relay: %x", wire)
	default:
	}

	if err := relayPeer.SendDatagram(encode(kindRelay, 0, 1, []byte{0x45})); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for mux.Snapshot().Counters.InvalidPackets == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	readCtx, cancelRead := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelRead()
	if packet, err := mux.ReceivePacket(readCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("relay payload reached TUN receive queue: packet=%x err=%v", packet, err)
	}
	snapshot = mux.Snapshot()
	if snapshot.Counters.RelaySent != 0 || snapshot.Counters.RelayReceived != 0 || snapshot.Counters.InvalidPackets == 0 {
		t.Fatalf("relay payload counters violate direct-required policy: %#v", snapshot.Counters)
	}
}

func TestDirectRequiredLossAndRelayReplacementRemainBackpressured(t *testing.T) {
	mux, _, cleanup := newDirectRequiredMux(t, time.Second)
	defer cleanup()
	directPeer, direct := connectionPair()
	if err := mux.ActivateDirect(9, direct); err != nil {
		t.Fatal(err)
	}
	if err := mux.SendPacket([]byte{0x45, 1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-directPeer.inbound:
	case <-time.After(time.Second):
		t.Fatal("direct path did not carry payload")
	}
	if !mux.DirectFailed(9) {
		t.Fatal("direct path did not fail")
	}
	mux.mu.Lock()
	generation, timer := mux.noPathGeneration, mux.noPathTimer
	mux.mu.Unlock()
	if timer == nil {
		t.Fatal("direct loss did not arm no-path deadline")
	}

	relayPeer, replacement := connectionPair()
	if err := mux.ReplaceRelay(replacement); err != nil {
		t.Fatal(err)
	}
	mux.mu.Lock()
	gotGeneration, gotTimer := mux.noPathGeneration, mux.noPathTimer
	mux.mu.Unlock()
	if gotGeneration != generation || gotTimer != timer {
		t.Fatal("relay replacement reset the direct-recovery deadline")
	}
	snapshot := mux.Snapshot()
	if snapshot.Selected != SelectedNone || !snapshot.RelayHealthy || snapshot.DirectHealthy {
		t.Fatalf("relay replacement became application path: %#v", snapshot)
	}
	if snapshot.Counters.Fallbacks != 0 {
		t.Fatalf("direct withdrawal was mislabeled as a relay fallback: %#v", snapshot.Counters)
	}
	sendCtx, cancelSend := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelSend()
	if err := mux.SendPacketContext(sendCtx, []byte{0x45, 2}); !errors.Is(err, ErrNoHealthyPath) {
		t.Fatalf("post-loss send returned %v", err)
	}
	select {
	case wire := <-relayPeer.inbound:
		t.Fatalf("post-loss payload traversed relay: %x", wire)
	default:
	}
	if snapshot := mux.Snapshot(); snapshot.Counters.RelaySent != 0 || snapshot.Counters.RelayReceived != 0 {
		t.Fatalf("relay counters advanced in direct-required mode: %#v", snapshot.Counters)
	}
}

func TestDirectRequiredRecoveryCancelsOriginalDeadline(t *testing.T) {
	mux, _, cleanup := newDirectRequiredMux(t, 80*time.Millisecond)
	defer cleanup()
	_, direct := connectionPair()
	if err := mux.ActivateDirect(1, direct); err != nil {
		t.Fatal(err)
	}
	if !mux.DirectFailed(1) {
		t.Fatal("direct failure was not applied")
	}
	time.Sleep(20 * time.Millisecond)
	_, recovered := connectionPair()
	if err := mux.ActivateDirect(1, recovered); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-mux.Errors():
		t.Fatalf("stale direct-recovery timer killed replacement: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if snapshot := mux.Snapshot(); snapshot.Selected != SelectedDirect || !snapshot.DirectHealthy {
		t.Fatalf("recovered direct path not selected: %#v", snapshot)
	}
}

func TestDirectRequiredProvisionalActivationCannotResetOutageOrCarryTraffic(t *testing.T) {
	mux, _, cleanup := newDirectRequiredMux(t, 500*time.Millisecond)
	defer cleanup()
	mux.mu.Lock()
	generation, timer := mux.noPathGeneration, mux.noPathTimer
	mux.mu.Unlock()
	if timer == nil {
		t.Fatal("direct-required startup did not arm no-path deadline")
	}

	directPeer, direct := connectionPair()
	if err := mux.PrepareDirect(1, direct); err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(1); err != nil {
		t.Fatal(err)
	}
	mux.mu.Lock()
	gotGeneration, gotTimer := mux.noPathGeneration, mux.noPathTimer
	mux.mu.Unlock()
	if gotGeneration != generation || gotTimer != timer {
		t.Fatal("provisional selection reset the original no-path deadline")
	}
	if snapshot := mux.Snapshot(); snapshot.Selected != SelectedNone || snapshot.DirectHealthy || snapshot.DirectInstanceID != 0 {
		t.Fatalf("provisional direct path became externally authoritative: %#v", snapshot)
	}

	sendCtx, cancelSend := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelSend()
	if err := mux.SendPacketContext(sendCtx, []byte{0x45, 3}); !errors.Is(err, ErrNoHealthyPath) {
		t.Fatalf("provisional send returned %v", err)
	}
	select {
	case wire := <-directPeer.inbound:
		t.Fatalf("provisional direct path carried payload: %x", wire)
	default:
	}

	mux.AbortDirect(1)
	mux.mu.Lock()
	gotGeneration, gotTimer = mux.noPathGeneration, mux.noPathTimer
	mux.mu.Unlock()
	if gotGeneration != generation || gotTimer != timer {
		t.Fatal("aborted activation reset the original no-path deadline")
	}
}

func TestDirectRequiredCommitMakesPathAuthoritativeAndCancelsDeadline(t *testing.T) {
	mux, _, cleanup := newDirectRequiredMux(t, 500*time.Millisecond)
	defer cleanup()
	directPeer, direct := connectionPair()
	if err := mux.PrepareDirect(1, direct); err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(1); err != nil {
		t.Fatal(err)
	}
	if err := mux.CommitDirect(1); err != nil {
		t.Fatal(err)
	}
	mux.mu.Lock()
	timer := mux.noPathTimer
	mux.mu.Unlock()
	if timer != nil {
		t.Fatal("committed direct path did not cancel no-path deadline")
	}
	if snapshot := mux.Snapshot(); snapshot.Selected != SelectedDirect || !snapshot.DirectHealthy || snapshot.DirectInstanceID == 0 {
		t.Fatalf("committed direct path is not authoritative: %#v", snapshot)
	}
	if err := mux.SendPacket([]byte{0x45, 4}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-directPeer.inbound:
	case <-time.After(time.Second):
		t.Fatal("committed direct path did not carry payload")
	}
}

func TestDirectRequiredReplacementKeepsOldPathAuthoritativeUntilCommit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := NewWithOptions(ctx, 1200, relay, Options{
		RequireDirect: true, DirectProgressTimeout: 100 * time.Millisecond,
		NoPathRecoveryTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	old := newProgressAwareConnection()
	if err := mux.ActivateDirect(1, old); err != nil {
		t.Fatal(err)
	}
	if err := mux.SendPacket([]byte{0x45, 5}); err != nil {
		t.Fatal(err)
	}
	oldBinding := old.deliveryBinding()
	if oldBinding.Acknowledge == nil {
		t.Fatal("old direct path has no delivery binding")
	}
	_, replacement := connectionPair()
	if err := mux.PrepareDirect(2, replacement); err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(2); err != nil {
		t.Fatal(err)
	}
	if !oldBinding.Acknowledge(1) {
		t.Fatal("valid delayed acknowledgement for committed old path was rejected")
	}
	time.Sleep(2 * 100 * time.Millisecond)
	snapshot := mux.Snapshot()
	if snapshot.Selected != SelectedDirect || !snapshot.DirectHealthy || snapshot.DirectEpoch != 1 ||
		snapshot.Counters.WatchdogFailure != 0 {
		t.Fatalf("provisional replacement demoted committed old path: %#v", snapshot)
	}
	mux.AbortDirect(2)
	if snapshot := mux.Snapshot(); snapshot.Selected != SelectedDirect || snapshot.DirectEpoch != 1 {
		t.Fatalf("abort did not preserve exact committed old path: %#v", snapshot)
	}
}

func TestDirectRequiredOldPathBlackholeDuringProvisionalReplacementStartsOneDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := NewWithOptions(ctx, 1200, relay, Options{
		RequireDirect: true, DirectProgressTimeout: 30 * time.Millisecond,
		NoPathRecoveryTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	old := newProgressAwareConnection()
	if err := mux.ActivateDirect(1, old); err != nil {
		t.Fatal(err)
	}
	old.dropSend.Store(true)
	_, replacement := connectionPair()
	if err := mux.PrepareDirect(2, replacement); err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(2); err != nil {
		t.Fatal(err)
	}
	if err := mux.SendPacket([]byte{0x45, 6}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for mux.Snapshot().Counters.WatchdogFailure == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	snapshot := mux.Snapshot()
	if snapshot.Selected != SelectedNone || snapshot.DirectHealthy || snapshot.Counters.WatchdogFailure != 1 ||
		snapshot.Counters.Fallbacks != 0 {
		t.Fatalf("blackholed committed path did not fail closed: %#v", snapshot)
	}
	mux.mu.Lock()
	generation, timer := mux.noPathGeneration, mux.noPathTimer
	mux.mu.Unlock()
	if timer == nil {
		t.Fatal("committed-path blackhole did not arm no-path deadline")
	}
	mux.AbortDirect(2)
	mux.mu.Lock()
	gotGeneration, gotTimer := mux.noPathGeneration, mux.noPathTimer
	mux.mu.Unlock()
	if gotGeneration != generation || gotTimer != timer {
		t.Fatal("aborting provisional replacement extended the outage deadline")
	}
}

func TestDirectRequiredCommittedReplacementRetainsOldACKAndReceiveDrain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := NewDirectRequired(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	old := newProgressAwareConnection()
	if err := mux.ActivateDirect(1, old); err != nil {
		t.Fatal(err)
	}
	if err := mux.SendPacket([]byte{0x45, 7}); err != nil {
		t.Fatal(err)
	}
	oldBinding := old.deliveryBinding()
	_, replacement := connectionPair()
	if err := mux.PrepareDirect(2, replacement); err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(2); err != nil {
		t.Fatal(err)
	}
	if err := mux.CommitDirect(2); err != nil {
		t.Fatal(err)
	}
	if oldBinding.Acknowledge == nil || !oldBinding.Acknowledge(1) {
		t.Fatal("delayed valid acknowledgement from receive-draining path was rejected")
	}
	old.inbound <- encode(kindDirect, 1, 1, []byte{0x45, 8})
	receiveCtx, cancelReceive := context.WithTimeout(context.Background(), time.Second)
	defer cancelReceive()
	packet, err := mux.ReceivePacket(receiveCtx)
	if err != nil || len(packet) != 2 || packet[1] != 8 {
		t.Fatalf("old in-flight datagram was not accepted during receive drain: packet=%x err=%v", packet, err)
	}
	snapshot := mux.Snapshot()
	if snapshot.Selected != SelectedDirect || snapshot.DirectEpoch != 2 || snapshot.Counters.DirectProgress == 0 {
		t.Fatalf("old drain disturbed committed replacement: %#v", snapshot)
	}
}
