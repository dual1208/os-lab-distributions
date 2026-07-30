package datapath

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRelayOnlyLossRecoversWithinSameMuxInvocation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := NewWithOptions(ctx, 1200, relay, Options{
		NoPathRecoveryTimeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	mux.relayFailed(mux.relay.id)
	waitCtx, cancelWait := context.WithTimeout(ctx, time.Second)
	defer cancelWait()
	recovered := make(chan error, 1)
	go func() { recovered <- mux.WaitForHealthy(waitCtx) }()

	peer, replacement := connectionPair()
	time.Sleep(25 * time.Millisecond)
	if err := mux.ReplaceRelay(replacement); err != nil {
		t.Fatal(err)
	}
	if err := <-recovered; err != nil {
		t.Fatalf("waiter did not observe authenticated relay recovery: %v", err)
	}
	select {
	case err := <-mux.Errors():
		t.Fatalf("stale no-path deadline killed recovered mux: %v", err)
	case <-time.After(175 * time.Millisecond):
	}
	if err := mux.SendPacket([]byte{0x45, 0x00}); err != nil {
		t.Fatalf("recovered relay send failed: %v", err)
	}
	select {
	case <-peer.inbound:
	case <-time.After(time.Second):
		t.Fatal("recovered relay did not carry traffic")
	}
}

func TestNoPathNotificationsCannotExtendFatalDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := NewWithOptions(ctx, 1200, relay, Options{
		NoPathRecoveryTimeout: 40 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	started := time.Now()
	mux.relayFailed(mux.relay.id)
	for index := 0; index < 5; index++ {
		time.Sleep(8 * time.Millisecond)
		mux.notify()
	}
	select {
	case err := <-mux.Errors():
		if !errors.Is(err, ErrNoHealthyPath) {
			t.Fatalf("deadline returned %v", err)
		}
		if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
			t.Fatalf("repeated notifications extended no-path deadline: %v", elapsed)
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("no-path deadline did not fail closed")
	}
}

func TestDirectFailureDuringRelayRecoveryCanUseReplacement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := NewWithOptions(ctx, 1200, relay, Options{
		NoPathRecoveryTimeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	_, direct := connectionPair()
	if err := mux.ActivateDirect(7, direct); err != nil {
		t.Fatal(err)
	}
	mux.relayFailed(mux.relay.id)
	if !mux.DirectFailed(7) {
		t.Fatal("active direct path was not failed")
	}
	if snapshot := mux.Snapshot(); snapshot.Selected != SelectedNone {
		t.Fatalf("expected bounded no-path gap, got %#v", snapshot)
	}

	_, replacement := connectionPair()
	if err := mux.ReplaceRelay(replacement); err != nil {
		t.Fatal(err)
	}
	waitCtx, cancelWait := context.WithTimeout(ctx, time.Second)
	defer cancelWait()
	if err := mux.WaitForHealthy(waitCtx); err != nil {
		t.Fatalf("replacement relay was not selected: %v", err)
	}
	select {
	case err := <-mux.Errors():
		t.Fatalf("recovered relay was killed: %v", err)
	case <-time.After(175 * time.Millisecond):
	}
}

func TestWaitForHealthyHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	_, relay := connectionPair()
	mux, err := NewWithOptions(ctx, 1200, relay, Options{
		NoPathRecoveryTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	mux.relayFailed(mux.relay.id)
	waitCtx, cancelWait := context.WithCancel(context.Background())
	cancelWait()
	if err := mux.WaitForHealthy(waitCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter returned %v", err)
	}
	cancel()
}

func TestTerminalSendFailureIsClassifiedAsTransientNoPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := NewWithOptions(ctx, 1200, relay, Options{
		NoPathRecoveryTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	relay.setSendError(errors.New("injected relay failure"))
	sendCtx, cancelSend := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancelSend()
	if err := mux.SendPacketContext(sendCtx, []byte{0x45}); !errors.Is(err, ErrNoHealthyPath) {
		t.Fatalf("terminal path send was not recoverable: %v", err)
	}
}

func TestAmbiguousSendRecoveryReusesSequenceAndSuppressesDuplicate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstSender, firstReceiver := connectionPair()
	sender, err := NewWithOptions(ctx, 1200, &deliverThenFailConnection{fakeConnection: firstSender}, Options{
		NoPathRecoveryTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver, err := New(ctx, 1200, firstReceiver)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()

	payload := []byte{0x45, 0x00, 0x00, 0x14}
	sendDone := make(chan error, 1)
	go func() { sendDone <- sender.SendPacketContext(ctx, payload) }()
	if got := receiveWithin(t, receiver); string(got) != string(payload) {
		t.Fatalf("first ambiguous delivery=%x", got)
	}
	select {
	case <-sender.RelayRecoveryNeeded():
	case <-time.After(time.Second):
		t.Fatal("ambiguous send did not request relay recovery")
	}

	replacementSender, replacementReceiver := connectionPair()
	if err := receiver.ReplaceRelay(replacementReceiver); err != nil {
		t.Fatal(err)
	}
	if err := sender.ReplaceRelay(replacementSender); err != nil {
		t.Fatal(err)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("same-sequence recovery send failed: %v", err)
	}
	readCtx, cancelRead := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancelRead()
	if duplicate, err := receiver.ReceivePacket(readCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ambiguous packet was delivered twice: packet=%x err=%v", duplicate, err)
	}
	if got := receiver.Snapshot().Counters.DuplicatePacket; got != 1 {
		t.Fatalf("same-sequence retry was not replay-suppressed: duplicates=%d", got)
	}
}

func TestTerminalNoPathLatchRejectsAllLaterForwarding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := NewWithOptions(ctx, 1200, relay, Options{
		NoPathRecoveryTimeout: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	mux.inbound <- receivedPacket{payload: []byte{0x45}}
	mux.relayFailed(mux.relay.id)
	select {
	case err := <-mux.Errors():
		if !errors.Is(err, ErrNoHealthyPath) {
			t.Fatalf("terminal deadline returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal no-path deadline did not fire")
	}

	_, replacement := connectionPair()
	if err := mux.ReplaceRelay(replacement); !errors.Is(err, ErrNoHealthyPath) {
		t.Fatalf("post-deadline relay replacement returned %v", err)
	}
	select {
	case <-replacement.closed:
	case <-time.After(time.Second):
		t.Fatal("post-deadline relay candidate was not closed")
	}
	if err := mux.WaitForHealthy(context.Background()); !errors.Is(err, ErrNoHealthyPath) {
		t.Fatalf("post-deadline waiter returned %v", err)
	}
	if err := mux.SendPacketContext(context.Background(), []byte{0x45}); !errors.Is(err, ErrNoHealthyPath) {
		t.Fatalf("post-deadline sender returned %v", err)
	}
	if packet, err := mux.ReceivePacket(context.Background()); !errors.Is(err, ErrNoHealthyPath) {
		t.Fatalf("post-deadline buffered packet escaped: packet=%x err=%v", packet, err)
	}
}

func TestBlockedRetirementCannotDelayRecoverySignalOrDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base, _ := connectionPair()
	release := make(chan struct{})
	blocked := &blockingCloseConnection{
		fakeConnection: base,
		entered:        make(chan struct{}),
		release:        release,
	}
	mux, err := NewWithOptions(ctx, 1200, blocked, Options{
		NoPathRecoveryTimeout: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	failed := make(chan struct{})
	go func() {
		mux.relayFailed(mux.relay.id)
		close(failed)
	}()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("retirement close was not reached")
	}
	select {
	case <-mux.RelayRecoveryNeeded():
	case <-time.After(20 * time.Millisecond):
		close(release)
		t.Fatal("blocking retirement delayed relay recovery signal")
	}
	select {
	case err := <-mux.Errors():
		if !errors.Is(err, ErrNoHealthyPath) {
			t.Fatalf("deadline returned %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		close(release)
		t.Fatal("blocking retirement delayed terminal deadline")
	}
	close(release)
	select {
	case <-failed:
	case <-time.After(time.Second):
		t.Fatal("retirement did not finish after release")
	}
}

func TestSendSerializationHonorsWaitingCallerDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base, peer := connectionPair()
	release := make(chan struct{})
	blocked := &blockingSendConnection{
		fakeConnection: base,
		entered:        make(chan struct{}),
		release:        release,
	}
	mux, err := New(ctx, 1200, blocked)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	first := make(chan error, 1)
	go func() { first <- mux.SendPacketContext(ctx, []byte{0x45, 1}) }()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("first send did not enter connection")
	}
	shortCtx, cancelShort := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancelShort()
	started := time.Now()
	if err := mux.SendPacketContext(shortCtx, []byte{0x45, 2}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting sender returned %v", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("waiting sender ignored deadline for %v", elapsed)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first sender failed: %v", err)
	}
	select {
	case <-peer.inbound:
	case <-time.After(time.Second):
		t.Fatal("first sender did not complete")
	}
}

func TestPreCanceledSendCannotDemoteHealthyPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := New(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	canceled, cancelSend := context.WithCancel(context.Background())
	cancelSend()
	if err := mux.SendPacketContext(canceled, []byte{0x45}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled sender returned %v", err)
	}
	snapshot := mux.Snapshot()
	if snapshot.Selected != SelectedRelay || !snapshot.RelayHealthy || snapshot.Counters.RelaySent != 0 {
		t.Fatalf("pre-canceled sender mutated healthy path: %#v", snapshot)
	}
}

type deliverThenFailConnection struct {
	*fakeConnection
}

type blockingCloseConnection struct {
	*fakeConnection
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

type blockingSendConnection struct {
	*fakeConnection
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (c *blockingSendConnection) SendDatagram(packet []byte) error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return c.fakeConnection.SendDatagram(packet)
}

func (c *blockingCloseConnection) Close(reason string) error {
	c.once.Do(func() {
		close(c.entered)
		<-c.release
	})
	return c.fakeConnection.Close(reason)
}

func (c *deliverThenFailConnection) SendDatagram(packet []byte) error {
	if err := c.fakeConnection.SendDatagram(packet); err != nil {
		return err
	}
	return errors.New("ambiguous send result after delivery")
}
