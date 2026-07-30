package datapath

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestProvisionalFirstPacketWaitsForDelayedReceiverCommit(t *testing.T) {
	a, cleanupA := newBufferedActivationMux(t, 1200)
	defer cleanupA()
	b, cleanupB := newBufferedActivationMux(t, 1200)
	defer cleanupB()

	aDirect, bDirect := connectionPair()
	for _, activation := range []struct {
		mux        *Mux
		connection Connection
	}{{a, aDirect}, {b, bDirect}} {
		if err := activation.mux.PrepareDirect(9, activation.connection); err != nil {
			t.Fatal(err)
		}
		if err := activation.mux.SelectDirect(9); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.CommitDirect(9); err != nil {
		t.Fatal(err)
	}

	first := []byte{0x45, 0x01}
	if err := a.SendPacket(first); err != nil {
		t.Fatal(err)
	}
	buffer, _ := waitForActivationPackets(t, b, 1)
	if got := b.Snapshot().Counters.DirectReceived; got != 0 {
		t.Fatalf("provisional packet counted as delivered: %d", got)
	}
	assertReceiveTimeout(t, b)

	// The same authenticated datagram is rejected against the private window;
	// commit must not evaluate the retained original a second time.
	if err := aDirect.SendDatagram(encode(kindDirect, 9, 1, first)); err != nil {
		t.Fatal(err)
	}
	waitForCounter(t, func() uint64 { return b.Snapshot().Counters.DuplicatePacket }, 1)
	if err := b.CommitDirect(9); err != nil {
		t.Fatal(err)
	}
	if got := receiveWithin(t, b); !bytes.Equal(got, first) {
		t.Fatalf("released first packet=%x want=%x", got, first)
	}
	assertActivationBufferZero(t, b, buffer)

	if err := aDirect.SendDatagram(encode(kindDirect, 9, 1, first)); err != nil {
		t.Fatal(err)
	}
	waitForCounter(t, func() uint64 { return b.Snapshot().Counters.DuplicatePacket }, 2)
	assertReceiveTimeout(t, b)

	second := []byte{0x45, 0x02}
	if err := a.SendPacket(second); err != nil {
		t.Fatal(err)
	}
	if got := receiveWithin(t, b); !bytes.Equal(got, second) {
		t.Fatalf("post-barrier packet=%x want=%x", got, second)
	}
	if snapshot := b.Snapshot(); snapshot.Counters.DirectReceived != 2 || snapshot.Counters.QueueDrops != 0 {
		t.Fatalf("unexpected receiver counters after ordered release: %#v", snapshot.Counters)
	}
}

func TestProvisionalPacketOverflowAbortsWholeCandidateAndKeepsOldPath(t *testing.T) {
	mux, cleanup := newBufferedActivationMux(t, 1200)
	defer cleanup()
	oldPeer, old := connectionPair()
	if err := mux.ActivateDirect(1, old); err != nil {
		t.Fatal(err)
	}

	peer, candidate := connectionPair()
	if err := mux.PrepareDirect(2, candidate); err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(2); err != nil {
		t.Fatal(err)
	}
	buffer, _ := waitForActivationPackets(t, mux, 0)
	for sequence := 1; sequence <= maxActivationPackets; sequence++ {
		if err := peer.SendDatagram(encode(kindDirect, 2, uint64(sequence), []byte{0x45})); err != nil {
			t.Fatal(err)
		}
	}
	waitForActivationPackets(t, mux, maxActivationPackets)
	if err := peer.SendDatagram(encode(kindDirect, 2, maxActivationPackets+1, []byte{0x45})); err != nil {
		t.Fatal(err)
	}
	waitForClosed(t, candidate)
	assertActivationBufferZero(t, mux, buffer)

	snapshot := mux.Snapshot()
	if snapshot.Selected != SelectedDirect || !snapshot.DirectHealthy || snapshot.DirectEpoch != 1 ||
		snapshot.Counters.DirectReceived != 0 {
		t.Fatalf("overflow disturbed old committed path or delivered buffered data: %#v", snapshot)
	}
	if err := mux.CommitDirect(2); !errors.Is(err, ErrStalePath) {
		t.Fatalf("overflowed candidate committed: %v", err)
	}
	if err := mux.SendPacket([]byte{0x45, 0xaa}); err != nil {
		t.Fatalf("old committed path stopped after candidate overflow: %v", err)
	}
	select {
	case <-oldPeer.inbound:
	case <-time.After(time.Second):
		t.Fatal("old committed path did not remain live")
	}
	assertReceiveTimeout(t, mux)
}

func TestProvisionalByteOverflowAbortsWithoutEviction(t *testing.T) {
	mux, cleanup := newBufferedActivationMux(t, 65535)
	defer cleanup()
	peer, candidate := connectionPair()
	if err := mux.PrepareDirect(3, candidate); err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(3); err != nil {
		t.Fatal(err)
	}
	buffer, _ := waitForActivationPackets(t, mux, 0)
	full := bytes.Repeat([]byte{0x45}, 65535)
	for sequence := uint64(1); sequence <= 8; sequence++ {
		if err := peer.SendDatagram(encode(kindDirect, 3, sequence, full)); err != nil {
			t.Fatal(err)
		}
	}
	waitForActivationPackets(t, mux, 8)
	if err := peer.SendDatagram(encode(kindDirect, 3, 9, bytes.Repeat([]byte{0x45}, 9))); err != nil {
		t.Fatal(err)
	}
	waitForClosed(t, candidate)
	assertActivationBufferZero(t, mux, buffer)
	assertReceiveTimeout(t, mux)
}

func TestCommitReservesEntireInboundCapacityOrAborts(t *testing.T) {
	mux, cleanup := newBufferedActivationMux(t, 1200)
	defer cleanup()
	peer, candidate := connectionPair()
	if err := mux.PrepareDirect(4, candidate); err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(4); err != nil {
		t.Fatal(err)
	}
	for sequence := uint64(1); sequence <= 2; sequence++ {
		if err := peer.SendDatagram(encode(kindDirect, 4, sequence, []byte{0x45, byte(sequence)})); err != nil {
			t.Fatal(err)
		}
	}
	buffer, _ := waitForActivationPackets(t, mux, 2)
	mux.inboundMu.Lock()
	for len(mux.inbound) < cap(mux.inbound)-1 {
		mux.inbound <- receivedPacket{payload: []byte{0xee}}
	}
	prefilled := len(mux.inbound)
	mux.inboundMu.Unlock()

	if err := mux.CommitDirect(4); !errors.Is(err, ErrActivationCapacity) {
		t.Fatalf("capacity-starved commit returned %v", err)
	}
	if got := len(mux.inbound); got != prefilled {
		t.Fatalf("commit partially released provisional FIFO: len=%d want=%d", got, prefilled)
	}
	if snapshot := mux.Snapshot(); snapshot.Selected != SelectedNone || snapshot.Counters.DirectReceived != 0 ||
		snapshot.Counters.QueueDrops != 0 {
		t.Fatalf("failed reservation exposed candidate data: %#v", snapshot)
	}
	assertActivationBufferZero(t, mux, buffer)
	waitForClosed(t, candidate)
}

func TestAbortDoesNotPoisonSameEpochRetryReplay(t *testing.T) {
	mux, cleanup := newBufferedActivationMux(t, 1200)
	defer cleanup()
	_, initial := connectionPair()
	if err := mux.ActivateDirect(5, initial); err != nil {
		t.Fatal(err)
	}
	if !mux.DirectFailed(5) {
		t.Fatal("could not create an authorized same-epoch retry state")
	}

	firstPeer, first := connectionPair()
	if err := mux.PrepareDirect(5, first); err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(5); err != nil {
		t.Fatal(err)
	}
	payload := []byte{0x45, 0x55}
	if err := firstPeer.SendDatagram(encode(kindDirect, 5, 1, payload)); err != nil {
		t.Fatal(err)
	}
	firstBuffer, _ := waitForActivationPackets(t, mux, 1)
	mux.AbortDirect(5)
	assertActivationBufferZero(t, mux, firstBuffer)
	waitForClosed(t, first)

	secondPeer, second := connectionPair()
	if err := mux.PrepareDirect(5, second); err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(5); err != nil {
		t.Fatal(err)
	}
	if err := secondPeer.SendDatagram(encode(kindDirect, 5, 1, payload)); err != nil {
		t.Fatal(err)
	}
	waitForActivationPackets(t, mux, 1)
	if err := mux.CommitDirect(5); err != nil {
		t.Fatal(err)
	}
	if got := receiveWithin(t, mux); !bytes.Equal(got, payload) {
		t.Fatalf("same-sequence retry was poisoned by aborted private replay state: %x", got)
	}
	assertReceiveTimeout(t, mux)
}

func TestStalePendingFailureCannotAbortSameEpochReplacement(t *testing.T) {
	mux, cleanup := newBufferedActivationMux(t, 1200)
	defer cleanup()
	_, initial := connectionPair()
	if err := mux.ActivateDirect(6, initial); err != nil {
		t.Fatal(err)
	}
	if !mux.DirectFailed(6) {
		t.Fatal("could not create retry state")
	}

	_, stale := connectionPair()
	staleID, err := mux.PrepareDirectWithInstance(6, stale)
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(6); err != nil {
		t.Fatal(err)
	}
	mux.AbortDirect(6)

	peer, replacement := connectionPair()
	replacementID, err := mux.PrepareDirectWithInstance(6, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(6); err != nil {
		t.Fatal(err)
	}
	mux.directReceiveFailed(6, staleID)
	mux.mu.Lock()
	stillPending := mux.pending.id == replacementID && mux.pending.healthy && mux.rollbackEpoch == 6
	mux.mu.Unlock()
	if !stillPending {
		t.Fatal("stale exact-instance failure aborted the same-epoch replacement")
	}
	payload := []byte{0x45, 0x66}
	if err := peer.SendDatagram(encode(kindDirect, 6, 1, payload)); err != nil {
		t.Fatal(err)
	}
	waitForActivationPackets(t, mux, 1)
	if err := mux.CommitDirect(6); err != nil {
		t.Fatal(err)
	}
	if got := receiveWithin(t, mux); !bytes.Equal(got, payload) {
		t.Fatalf("replacement payload=%x want=%x", got, payload)
	}
}

func TestActivationExpiryRetirementAndCloseZeroAccounting(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(*Mux, uint64, uint64, *activationBuffer)
	}{
		{"expiry", func(mux *Mux, epoch, id uint64, buffer *activationBuffer) {
			mux.activationBufferExpired(epoch, id, buffer)
		}},
		{"retirement", func(mux *Mux, _, _ uint64, _ *activationBuffer) { mux.RetireDirect() }},
		{"close", func(mux *Mux, _, _ uint64, _ *activationBuffer) { mux.Close() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			mux, cleanup := newBufferedActivationMux(t, 1200)
			defer cleanup()
			peer, candidate := connectionPair()
			id, err := mux.PrepareDirectWithInstance(7, candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := mux.SelectDirect(7); err != nil {
				t.Fatal(err)
			}
			if err := peer.SendDatagram(encode(kindDirect, 7, 1, []byte{0x45})); err != nil {
				t.Fatal(err)
			}
			buffer, _ := waitForActivationPackets(t, mux, 1)
			test.run(mux, 7, id, buffer)
			assertActivationBufferZero(t, mux, buffer)
			waitForClosed(t, candidate)
			if got := mux.Snapshot().Counters.DirectReceived; got != 0 {
				t.Fatalf("discarded activation delivered %d packets", got)
			}
		})
	}
}

func newBufferedActivationMux(t *testing.T, mtu int) (*Mux, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	_, relay := connectionPair()
	mux, err := NewWithOptions(ctx, mtu, relay, Options{
		RequireDirect: true, DirectProgressTimeout: time.Second, NoPathRecoveryTimeout: 10 * time.Second,
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return mux, func() {
		mux.Close()
		cancel()
	}
}

func waitForActivationPackets(t *testing.T, mux *Mux, want int) (*activationBuffer, pathSlot) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		mux.mu.Lock()
		slot := mux.pending
		buffer := slot.activation
		got := -1
		if buffer != nil {
			got = len(buffer.packets)
		}
		mux.mu.Unlock()
		if buffer != nil && got == want {
			return buffer, slot
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending activation packets=%d want=%d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForCounter(t *testing.T, load func() uint64, want uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for load() < want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := load(); got != want {
		t.Fatalf("counter=%d want=%d", got, want)
	}
}

func waitForClosed(t *testing.T, connection *fakeConnection) {
	t.Helper()
	select {
	case <-connection.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("candidate connection remained open")
	}
}

func assertActivationBufferZero(t *testing.T, mux *Mux, buffer *activationBuffer) {
	t.Helper()
	mux.mu.Lock()
	packets, byteCount := len(buffer.packets), buffer.bytes
	replay, base, hadBase := buffer.replay, buffer.base, buffer.hadBase
	mux.mu.Unlock()
	if packets != 0 || byteCount != 0 || replay != (sequenceWindow{}) || base != (sequenceWindow{}) || hadBase {
		t.Fatalf("activation accounting retained packets=%d bytes=%d had_base=%t", packets, byteCount, hadBase)
	}
	select {
	case <-buffer.release:
	default:
		t.Fatal("discard/release barrier remained open")
	}
}

func assertReceiveTimeout(t *testing.T, mux *Mux) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if packet, err := mux.ReceivePacket(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unexpected packet=%x err=%v", packet, err)
	}
}
