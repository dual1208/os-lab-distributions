package datapath

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

func TestWarmRelayCarriesPacketEnvelope(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	aConnection, bConnection := connectionPair()
	a, err := New(ctx, 1280, aConnection)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(ctx, 1280, bConnection)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	payload := []byte{0x45, 0, 0, 20}
	if err := a.SendPacket(payload); err != nil {
		t.Fatal(err)
	}
	got := receiveWithin(t, b)
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload=%x want=%x", got, payload)
	}
	if snapshot := a.Snapshot(); snapshot.Selected != SelectedRelay || snapshot.Counters.RelaySent != 1 || snapshot.Counters.DirectSent != 0 {
		t.Fatalf("unexpected sender snapshot: %#v", snapshot)
	}
}

func TestValidatedDirectSelectionStopsRelayForwarding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	aRelay, bRelay := connectionPair()
	a, _ := New(ctx, 1280, aRelay)
	b, _ := New(ctx, 1280, bRelay)
	defer a.Close()
	defer b.Close()
	aDirect, bDirect := connectionPair()
	if err := a.ActivateDirect(4, aDirect); err != nil {
		t.Fatal(err)
	}
	if err := b.ActivateDirect(4, bDirect); err != nil {
		t.Fatal(err)
	}
	for sequence := 0; sequence < 100; sequence++ {
		payload := []byte{0x45, byte(sequence)}
		if err := a.SendPacket(payload); err != nil {
			t.Fatal(err)
		}
		if got := receiveWithin(t, b); !bytes.Equal(got, payload) {
			t.Fatalf("packet %d mismatch: %x", sequence, got)
		}
	}
	if snapshot := a.Snapshot(); snapshot.Selected != SelectedDirect || snapshot.Counters.DirectSent != 100 || snapshot.Counters.RelaySent != 0 {
		t.Fatalf("direct transfer used relay: %#v", snapshot)
	}
	if snapshot := b.Snapshot(); snapshot.Counters.DirectReceived != 100 || snapshot.Counters.RelayReceived != 0 {
		t.Fatalf("direct receiver counters wrong: %#v", snapshot)
	}
}

func TestDirectSendFailureFallsBackToWarmRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	aRelay, bRelay := connectionPair()
	a, _ := New(ctx, 1280, aRelay)
	b, _ := New(ctx, 1280, bRelay)
	defer a.Close()
	defer b.Close()
	aDirect, bDirect := connectionPair()
	a.ActivateDirect(9, aDirect)
	b.ActivateDirect(9, bDirect)
	aDirect.setSendError(errors.New("direct path failed"))
	payload := []byte{0x45, 9}
	if err := a.SendPacket(payload); err != nil {
		t.Fatalf("warm fallback failed: %v", err)
	}
	if got := receiveWithin(t, b); !bytes.Equal(got, payload) {
		t.Fatalf("fallback payload=%x", got)
	}
	snapshot := a.Snapshot()
	if snapshot.Selected != SelectedRelay || snapshot.DirectHealthy || snapshot.Counters.Fallbacks != 1 || snapshot.Counters.RelaySent != 1 {
		t.Fatalf("unexpected fallback snapshot: %#v", snapshot)
	}
}

func TestDatagramCapacityShrinkDemotesPathAndUsesCapableFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	aRelay, bRelay := connectionPair()
	a, _ := New(ctx, 1200, aRelay)
	b, _ := New(ctx, 1200, bRelay)
	defer a.Close()
	defer b.Close()
	aDirect, bDirect := connectionPair()
	if err := a.ActivateDirect(3, aDirect); err != nil {
		t.Fatal(err)
	}
	if err := b.ActivateDirect(3, bDirect); err != nil {
		t.Fatal(err)
	}
	aDirect.setSendError(&quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1000})
	payload := bytes.Repeat([]byte{0x45}, 1200)
	if err := a.SendPacket(payload); err != nil {
		t.Fatalf("capable warm path was not used: %v", err)
	}
	if got := receiveWithin(t, b); !bytes.Equal(got, payload) {
		t.Fatal("fallback payload mismatch")
	}
	snapshot := a.Snapshot()
	if snapshot.Selected != SelectedRelay || snapshot.DirectHealthy || snapshot.Counters.RelaySent != 1 {
		t.Fatalf("capacity shrink did not demote direct path: %#v", snapshot)
	}
}

func TestSupersededPreparationClosesOldPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, _ := New(ctx, 1200, relay)
	defer mux.Close()
	_, first := connectionPair()
	_, second := connectionPair()
	if err := mux.PrepareDirect(1, first); err != nil {
		t.Fatal(err)
	}
	if err := mux.PrepareDirect(2, second); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first.closed:
	case <-time.After(time.Second):
		t.Fatal("superseded prepared connection remained open")
	}
	if err := mux.SelectDirect(2); err != nil {
		t.Fatal(err)
	}
}

func TestFailedActivationRestoresOldDirectWhenRelayIsDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, _ := New(ctx, 1200, relay)
	defer mux.Close()
	oldSender, oldReceiver := connectionPair()
	if err := mux.ActivateDirect(1, oldSender); err != nil {
		t.Fatal(err)
	}
	mux.relayFailed(mux.relay.id)
	_, replacement := connectionPair()
	if err := mux.PrepareDirect(2, replacement); err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(2); err != nil {
		t.Fatal(err)
	}
	mux.AbortDirect(2)
	snapshot := mux.Snapshot()
	if snapshot.Selected != SelectedDirect || snapshot.DirectEpoch != 1 || !snapshot.DirectHealthy || snapshot.RelayHealthy {
		t.Fatalf("old direct path was not restored: %#v", snapshot)
	}
	payload := []byte{0x45, 0x01}
	if err := mux.SendPacket(payload); err != nil {
		t.Fatalf("restored direct send failed: %v", err)
	}
	select {
	case wire := <-oldReceiver.inbound:
		_, epoch, _, got, err := decode(wire, 1200)
		if err != nil || epoch != 1 || !bytes.Equal(got, payload) {
			t.Fatalf("restored direct payload mismatch: epoch=%d err=%v", epoch, err)
		}
	case <-time.After(time.Second):
		t.Fatal("restored direct path did not transmit")
	}
	select {
	case <-replacement.closed:
	case <-time.After(time.Second):
		t.Fatal("aborted replacement remained open")
	}
}

func TestDuplicateAcrossSameEpochDirectRetryDeliveredOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, _ := New(ctx, 1200, relay)
	defer mux.Close()
	_, firstDirect := connectionPair()
	if err := mux.ActivateDirect(2, firstDirect); err != nil {
		t.Fatal(err)
	}
	payload := []byte{0x45, 1}
	firstDirect.inbound <- encode(kindDirect, 2, 77, payload)
	if got := receiveWithin(t, mux); !bytes.Equal(got, payload) {
		t.Fatalf("payload=%x", got)
	}
	if !mux.DirectFailed(2) {
		t.Fatal("first direct path did not fail")
	}
	_, retryDirect := connectionPair()
	if err := mux.ActivateDirect(2, retryDirect); err != nil {
		t.Fatal(err)
	}
	retryDirect.inbound <- encode(kindDirect, 2, 77, payload)
	ctxRead, cancelRead := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelRead()
	if _, err := mux.ReceivePacket(ctxRead); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("duplicate delivered: %v", err)
	}
	if snapshot := mux.Snapshot(); snapshot.Counters.DuplicatePacket != 1 {
		t.Fatalf("duplicate not counted: %#v", snapshot)
	}
}

func TestReplacedDirectCannotClearOrInjectIntoNewEpoch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, _ := New(ctx, 1280, relay)
	defer mux.Close()
	_, oldDirect := connectionPair()
	_, newDirect := connectionPair()
	mux.ActivateDirect(1, oldDirect)
	err := mux.ActivateDirect(2, newDirect)
	if err != nil {
		t.Fatalf("replacement failed: %v", err)
	}
	oldDirect.inbound <- encode(kindDirect, 1, 1, []byte{0x45})
	if got := receiveWithin(t, mux); !bytes.Equal(got, []byte{0x45}) {
		t.Fatalf("bounded draining packet lost: %x", got)
	}
	mux.mu.Lock()
	var retiredID uint64
	for id := range mux.draining {
		retiredID = id
	}
	mux.mu.Unlock()
	if retiredID == 0 {
		t.Fatal("old direct path was not retained for bounded draining")
	}
	mux.expireDraining(retiredID)
	select {
	case <-oldDirect.closed:
	case <-time.After(time.Second):
		t.Fatal("expired direct drain was not closed")
	}
	oldDirect.inbound <- encode(kindDirect, 1, 2, []byte{0x45, 2})
	ctxRead, cancelRead := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelRead()
	if _, err := mux.ReceivePacket(ctxRead); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired direct path injected a packet: %v", err)
	}
	if mux.DirectFailed(1) {
		t.Fatal("stale direct failure cleared newer epoch")
	}
	snapshot := mux.Snapshot()
	if snapshot.Selected != SelectedDirect || !snapshot.DirectHealthy || snapshot.DirectEpoch != 2 {
		t.Fatalf("new direct path disturbed: %#v", snapshot)
	}
}

func TestSequenceWindowAllowsReorderAndRejectsReplayAndAncientPackets(t *testing.T) {
	var window sequenceWindow
	for _, sequence := range []uint64{1, 4, 3, 2, 4098} {
		if !window.Accept(sequence) {
			t.Fatalf("fresh sequence %d rejected", sequence)
		}
	}
	if window.Accept(4) {
		t.Fatal("replayed sequence accepted")
	}
	if window.Accept(1) {
		t.Fatal("sequence outside replay window accepted")
	}
	if !window.Accept(4097) {
		t.Fatal("in-window reordered packet rejected")
	}
}

func TestEnvelopeRejectsReservedBitsAndPathEpochMismatch(t *testing.T) {
	wire := encode(kindDirect, 3, 1, []byte{0x45})
	wire[5] = 1
	if _, _, _, _, err := decode(wire, 1280); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("reserved bits accepted: %v", err)
	}
	if _, _, _, _, err := decode(encode(kindRelay, 1, 1, []byte{0x45}), 1280); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("relay epoch accepted: %v", err)
	}
}

func receiveWithin(t *testing.T, mux *Mux) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	packet, err := mux.ReceivePacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

type fakeConnection struct {
	inbound chan []byte
	peer    *fakeConnection
	mu      sync.Mutex
	sendErr error
	closed  chan struct{}
	close   sync.Once
}

func connectionPair() (*fakeConnection, *fakeConnection) {
	a := &fakeConnection{inbound: make(chan []byte, 512), closed: make(chan struct{})}
	b := &fakeConnection{inbound: make(chan []byte, 512), closed: make(chan struct{})}
	a.peer, b.peer = b, a
	return a, b
}

func (c *fakeConnection) SendDatagram(packet []byte) error {
	c.mu.Lock()
	err := c.sendErr
	c.mu.Unlock()
	if err != nil {
		return err
	}
	copyOfPacket := append([]byte(nil), packet...)
	select {
	case <-c.closed:
		return errors.New("connection closed")
	case c.peer.inbound <- copyOfPacket:
		return nil
	}
}

func (c *fakeConnection) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, errors.New("connection closed")
	case packet := <-c.inbound:
		return packet, nil
	}
}

func (c *fakeConnection) Close(string) error {
	c.close.Do(func() { close(c.closed) })
	return nil
}

func (c *fakeConnection) setSendError(err error) {
	c.mu.Lock()
	c.sendErr = err
	c.mu.Unlock()
}
