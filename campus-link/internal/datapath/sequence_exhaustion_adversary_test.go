package datapath

import (
	"context"
	"math"
	"testing"
)

// Sequence zero is forbidden on the wire. Once the uint64 counter is
// exhausted, every later send must stay fail-closed; wrapping once and then
// resuming at sequence one would violate global monotonicity and replay safety.
func TestSendSequenceExhaustionIsPermanentlyFailClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, peer := connectionPair()
	mux, err := New(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	mux.sequence.Store(math.MaxUint64)
	for attempt := 0; attempt < 8; attempt++ {
		if err := mux.SendPacket([]byte{0x45}); err == nil {
			t.Fatalf("attempt %d resumed transmission after sequence exhaustion", attempt+1)
		}
	}
	select {
	case wire := <-peer.inbound:
		t.Fatalf("sequence exhaustion emitted a %d-byte datagram", len(wire))
	default:
	}
	if snapshot := mux.Snapshot(); snapshot.Counters.RelaySent != 0 || snapshot.Counters.DirectSent != 0 {
		t.Fatalf("sequence exhaustion advanced send counters: %#v", snapshot.Counters)
	}
}
