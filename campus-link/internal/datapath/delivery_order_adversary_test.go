package datapath

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// A localhost peer can accept a DATAGRAM and return its authenticated progress
// frame before SendDatagram returns to the sender. Recording lastSent only after
// SendDatagram returns discards that valid progress edge and later withdraws a
// healthy direct path.
func TestImmediatePeerDeliveryAcknowledgementIsNotLost(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, _ := connectionPair()
	mux, err := NewWithOptions(ctx, 1200, relay, Options{DirectProgressTimeout: 40 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	direct := newImmediateAcknowledgingConnection()
	if err := mux.ActivateDirect(51, direct); err != nil {
		t.Fatal(err)
	}
	if err := mux.SendPacket([]byte{0x45, 0x00}); err != nil {
		t.Fatal(err)
	}
	if !direct.acknowledged {
		t.Fatal("peer progress callback rejected an immediately delivered packet")
	}
	time.Sleep(3 * 40 * time.Millisecond)
	snapshot := mux.Snapshot()
	if snapshot.Selected != SelectedDirect || !snapshot.DirectHealthy || snapshot.Counters.Fallbacks != 0 {
		t.Fatalf("healthy direct path was withdrawn after an early valid acknowledgement: %#v", snapshot)
	}
	if snapshot.Counters.DirectProgress != 1 || snapshot.Counters.WatchdogFailure != 0 {
		t.Fatalf("immediate delivery progress was not recorded exactly once: %#v", snapshot.Counters)
	}
}

// Rolling back a failed higher-epoch activation restores the old direct path.
// If that path already had unacknowledged traffic, its watchdog obligation must
// be restored with it; otherwise one failed activation disables no-progress
// detection permanently for the old connection instance.
func TestActivationRollbackRearmsOutstandingDeliveryWatchdog(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, _ := connectionPair()
	mux, err := NewWithOptions(ctx, 1200, relay, Options{DirectProgressTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	oldDirect := newSilentDirectConnection()
	if err := mux.ActivateDirect(71, oldDirect); err != nil {
		t.Fatal(err)
	}
	if err := mux.SendPacket([]byte{0x45, 0x71}); err != nil {
		t.Fatal(err)
	}
	failedReplacement := newSilentDirectConnection()
	if err := mux.PrepareDirect(72, failedReplacement); err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(72); err != nil {
		t.Fatal(err)
	}
	mux.AbortDirect(72)
	if snapshot := mux.Snapshot(); snapshot.Selected != SelectedDirect || !snapshot.DirectHealthy || snapshot.DirectEpoch != 71 {
		t.Fatalf("rollback did not restore the prior direct path: %#v", snapshot)
	}

	time.Sleep(3 * 50 * time.Millisecond)
	snapshot := mux.Snapshot()
	if snapshot.Selected != SelectedRelay || snapshot.DirectHealthy || snapshot.Counters.Fallbacks != 1 ||
		snapshot.Counters.WatchdogFailure != 1 {
		t.Fatalf("rollback silently disabled the outstanding delivery watchdog: %#v", snapshot)
	}
}

type immediateAcknowledgingConnection struct {
	mu           sync.Mutex
	binding      DeliveryBinding
	closed       chan struct{}
	closeOnce    sync.Once
	acknowledged bool
}

func newImmediateAcknowledgingConnection() *immediateAcknowledgingConnection {
	return &immediateAcknowledgingConnection{closed: make(chan struct{})}
}

func (c *immediateAcknowledgingConnection) BindDelivery(binding DeliveryBinding) {
	c.mu.Lock()
	c.binding = binding
	c.mu.Unlock()
}

func (c *immediateAcknowledgingConnection) DatagramDelivered(uint64) {}

func (c *immediateAcknowledgingConnection) SendDatagram(packet []byte) error {
	_, _, sequence, _, err := decode(packet, 1200)
	if err != nil {
		return err
	}
	c.mu.Lock()
	binding := c.binding
	c.mu.Unlock()
	if binding.Acknowledge == nil {
		return errors.New("delivery binding unavailable")
	}
	c.acknowledged = binding.Acknowledge(sequence)
	return nil
}

func (c *immediateAcknowledgingConnection) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, errors.New("connection closed")
	}
}

func (c *immediateAcknowledgingConnection) Close(string) error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
