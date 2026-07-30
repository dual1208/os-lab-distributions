package datapath

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDuplicateAuthenticatedProgressIsIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, _ := connectionPair()
	mux, err := NewWithOptions(ctx, 1200, relay, Options{DirectProgressTimeout: 40 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	direct := newProgressAwareConnection()
	if err := mux.ActivateDirect(81, direct); err != nil {
		t.Fatal(err)
	}
	if err := mux.SendPacket([]byte{0x45, 0x81}); err != nil {
		t.Fatal(err)
	}
	binding := direct.deliveryBinding()
	if binding.Acknowledge == nil || !binding.Acknowledge(1) || !binding.Acknowledge(1) {
		t.Fatal("duplicate authenticated progress was not accepted idempotently")
	}
	time.Sleep(3 * 40 * time.Millisecond)
	snapshot := mux.Snapshot()
	if snapshot.Selected != SelectedDirect || !snapshot.DirectHealthy || snapshot.Counters.Fallbacks != 0 ||
		snapshot.Counters.WatchdogFailure != 0 || snapshot.Counters.DirectProgress != 1 {
		t.Fatalf("duplicate progress changed path health or counters: %#v", snapshot)
	}
}

// The site-a direct sender is blackholed while authenticated reverse traffic
// still makes progress. Reverse progress cannot prove delivery in the lost
// direction; site-a must select its warm relay within the watchdog bound.
func TestOneWayDirectBlackholeFallsBackDespiteReverseProgress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relayA, relayB := connectionPair()
	muxA, err := NewWithOptions(ctx, 1200, relayA, Options{DirectProgressTimeout: 60 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	muxB, err := NewWithOptions(ctx, 1200, relayB, Options{DirectProgressTimeout: 60 * time.Millisecond})
	if err != nil {
		muxA.Close()
		t.Fatal(err)
	}
	defer muxA.Close()
	defer muxB.Close()

	directA, directB := progressAwarePair()
	directA.dropSend.Store(true)
	if err := muxA.ActivateDirect(82, directA); err != nil {
		t.Fatal(err)
	}
	if err := muxB.ActivateDirect(82, directB); err != nil {
		t.Fatal(err)
	}
	if err := muxA.SendPacket([]byte{0x45, 0xa2}); err != nil {
		t.Fatalf("silent blackhole did not accept site-a enqueue: %v", err)
	}
	if err := muxB.SendPacket([]byte{0x45, 0xb2}); err != nil {
		t.Fatalf("reverse direct send: %v", err)
	}
	receiveCtx, cancelReceive := context.WithTimeout(ctx, time.Second)
	defer cancelReceive()
	packet, err := muxA.ReceivePacket(receiveCtx)
	if err != nil || len(packet) != 2 || packet[1] != 0xb2 {
		t.Fatalf("reverse direct progress precondition failed: packet=%x err=%v", packet, err)
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		snapshot := muxA.Snapshot()
		if snapshot.Selected == SelectedRelay && !snapshot.DirectHealthy && snapshot.Counters.Fallbacks == 1 &&
			snapshot.Counters.WatchdogFailure == 1 {
			if muxB.Snapshot().Counters.DirectProgress == 0 {
				t.Fatal("reverse direction never recorded its independent authenticated progress")
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("one-way loss was masked by reverse traffic: %#v / %#v", muxA.Snapshot(), muxB.Snapshot())
}

// At the timeout boundary, ACK acceptance and path withdrawal must be
// linearizable. If the exact-instance ACK returns true, a later timeout from
// the same generation cannot still demote that path.
func TestDeliveryAcknowledgementAndTimeoutAreLinearizable(t *testing.T) {
	const iterations = 1_000
	previousProcs := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previousProcs)
	for iteration := 0; iteration < iterations; iteration++ {
		ctx, cancel := context.WithCancel(context.Background())
		relay, _ := connectionPair()
		mux, err := NewWithOptions(ctx, 1200, relay, Options{DirectProgressTimeout: time.Hour})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		direct := newProgressAwareConnection()
		const epoch = uint64(83)
		if err := mux.ActivateDirect(epoch, direct); err != nil {
			mux.Close()
			cancel()
			t.Fatal(err)
		}
		if err := mux.SendPacket([]byte{0x45, 0x83}); err != nil {
			mux.Close()
			cancel()
			t.Fatal(err)
		}
		binding := direct.deliveryBinding()
		mux.mu.Lock()
		id, generation := mux.direct.id, mux.direct.progressGeneration
		mux.mu.Unlock()
		start := make(chan struct{})
		var joined sync.WaitGroup
		var accepted atomic.Bool
		joined.Add(2)
		go func() {
			defer joined.Done()
			<-start
			accepted.Store(binding.Acknowledge(1))
		}()
		go func() {
			defer joined.Done()
			<-start
			mux.directProgressExpired(epoch, id, generation)
		}()
		close(start)
		joined.Wait()
		snapshot := mux.Snapshot()
		if accepted.Load() && (snapshot.Selected != SelectedDirect || !snapshot.DirectHealthy || snapshot.Counters.WatchdogFailure != 0) {
			mux.Close()
			cancel()
			t.Fatalf("iteration %d: accepted ACK lost the timeout race: %#v", iteration, snapshot)
		}
		if !accepted.Load() && (snapshot.Selected != SelectedRelay || snapshot.DirectHealthy || snapshot.Counters.WatchdogFailure != 1) {
			mux.Close()
			cancel()
			t.Fatalf("iteration %d: timeout won without withdrawing the path: %#v", iteration, snapshot)
		}
		mux.Close()
		cancel()
	}
}

type progressAwareConnection struct {
	inbound   chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	binding   DeliveryBinding
	peer      *progressAwareConnection
	dropSend  atomic.Bool
}

func newProgressAwareConnection() *progressAwareConnection {
	return &progressAwareConnection{inbound: make(chan []byte, 16), closed: make(chan struct{})}
}

func progressAwarePair() (*progressAwareConnection, *progressAwareConnection) {
	a, b := newProgressAwareConnection(), newProgressAwareConnection()
	a.peer, b.peer = b, a
	return a, b
}

func (c *progressAwareConnection) BindDelivery(binding DeliveryBinding) {
	c.mu.Lock()
	c.binding = binding
	c.mu.Unlock()
}

func (c *progressAwareConnection) deliveryBinding() DeliveryBinding {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.binding
}

func (c *progressAwareConnection) DatagramDelivered(sequence uint64) {
	if c.peer == nil {
		return
	}
	binding := c.peer.deliveryBinding()
	if binding.Acknowledge != nil {
		binding.Acknowledge(sequence)
	}
}

func (c *progressAwareConnection) SendDatagram(packet []byte) error {
	if c.dropSend.Load() {
		return nil
	}
	if c.peer == nil {
		return nil
	}
	copyOfPacket := append([]byte(nil), packet...)
	select {
	case <-c.closed:
		return errors.New("connection closed")
	case <-c.peer.closed:
		return errors.New("peer closed")
	case c.peer.inbound <- copyOfPacket:
		return nil
	}
}

func (c *progressAwareConnection) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, errors.New("connection closed")
	case packet := <-c.inbound:
		return packet, nil
	}
}

func (c *progressAwareConnection) Close(string) error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
