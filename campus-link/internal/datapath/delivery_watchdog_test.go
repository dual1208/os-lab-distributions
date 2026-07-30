package datapath

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests are the red side of the direct-path delivery-watchdog contract.
// QUIC's SendDatagram returning nil means only that quic-go accepted the frame;
// it does not prove that the peer received it. A selected direct path therefore
// must not remain healthy forever when every accepted DATAGRAM disappears.

func TestSilentDirectDatagramLossDemotesToWarmRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, _ := connectionPair()
	mux, err := NewWithOptions(ctx, 1200, relay, Options{DirectProgressTimeout: 75 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	direct := newSilentDirectConnection()
	if err := mux.ActivateDirect(41, direct); err != nil {
		t.Fatal(err)
	}
	for sequence := 0; sequence < 32; sequence++ {
		if err := mux.SendPacket([]byte{0x45, byte(sequence)}); err != nil {
			t.Fatalf("enqueue %d: %v", sequence, err)
		}
	}
	if got := direct.accepted.Load(); got != 32 {
		t.Fatalf("accepted sends=%d want=32", got)
	}
	if snapshot := mux.Snapshot(); snapshot.Counters.DirectSent != 32 || snapshot.Selected != SelectedDirect {
		t.Fatalf("test did not establish the silent-enqueue precondition: %#v", snapshot)
	}

	assertDirectWithdrawnAfterNoProgress(t, mux)
}

func TestUnrelatedInboundTrafficCannotMaskOutboundDirectLoss(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, _ := connectionPair()
	mux, err := NewWithOptions(ctx, 1200, relay, Options{DirectProgressTimeout: 75 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	direct := newSilentDirectConnection()
	const epoch = 42
	if err := mux.ActivateDirect(epoch, direct); err != nil {
		t.Fatal(err)
	}
	if err := mux.SendPacket([]byte{0x45, 0xaa}); err != nil {
		t.Fatal(err)
	}

	// Valid inbound packets prove that the authenticated peer can send in the
	// other direction. They do not prove delivery of our silently lost packet,
	// so a future watchdog must advance only on a correlated, exporter-bound
	// peer delivery acknowledgement.
	trafficCtx, stopTraffic := context.WithCancel(ctx)
	defer stopTraffic()
	go func() {
		sequence := uint64(10_000)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-trafficCtx.Done():
				return
			case <-ticker.C:
				packet := encode(kindDirect, epoch, sequence, []byte{0x45, 0xbb})
				sequence++
				select {
				case direct.inbound <- packet:
				case <-trafficCtx.Done():
					return
				}
			}
		}
	}()
	go func() {
		for {
			if _, err := mux.ReceivePacket(trafficCtx); err != nil {
				return
			}
		}
	}()

	assertDirectWithdrawnAfterNoProgress(t, mux)
}

func assertDirectWithdrawnAfterNoProgress(t *testing.T, mux *Mux) {
	t.Helper()
	// This intentionally short test deadline is not a proposed production
	// timeout. The implementation should expose a clock/timeout dependency to
	// tests while using the longer normative production bound.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		snapshot := mux.Snapshot()
		if snapshot.Selected == SelectedRelay && !snapshot.DirectHealthy && snapshot.Counters.Fallbacks == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	snapshot := mux.Snapshot()
	t.Fatalf("nil DATAGRAM enqueue was treated as peer delivery; direct path was not withdrawn: %#v", snapshot)
}

type silentDirectConnection struct {
	inbound   chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	accepted  atomic.Uint64
}

func newSilentDirectConnection() *silentDirectConnection {
	return &silentDirectConnection{inbound: make(chan []byte, 128), closed: make(chan struct{})}
}

func (c *silentDirectConnection) SendDatagram([]byte) error {
	select {
	case <-c.closed:
		return errors.New("connection closed")
	default:
		c.accepted.Add(1)
		return nil
	}
}

func (c *silentDirectConnection) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, errors.New("connection closed")
	case packet := <-c.inbound:
		return packet, nil
	}
}

func (c *silentDirectConnection) Close(string) error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
