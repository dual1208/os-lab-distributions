package datapath

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// relayRecoveryCapable is the minimum mux contract needed by an edge-owned
// relay supervisor. RelayRecoveryNeeded must be an edge-triggered, coalescing
// notification: one unread notification is enough while the relay is down.
// ReplaceRelay receives an already authenticated and capacity-validated
// connection and atomically installs it as the warm fallback.
type relayRecoveryCapable interface {
	RelayRecoveryNeeded() <-chan struct{}
	ReplaceRelay(Connection) error
}

func TestRelayLossRequestsRecoveryAndReplacementPreservesDirect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	oldRelay := newRelayRecoveryConnection()
	mux, err := New(ctx, 1200, oldRelay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	direct := newRelayRecoveryConnection()
	if err := mux.ActivateDirect(7, direct); err != nil {
		t.Fatal(err)
	}
	recovery := requireRelayRecovery(t, mux)

	oldRelay.failReceive(errors.New("relay instance stopped"))
	waitRelayState(t, mux, false)
	select {
	case <-recovery.RelayRecoveryNeeded():
	case <-time.After(time.Second):
		t.Fatal("relay loss was silent; no bounded recovery could start")
	}
	if snapshot := mux.Snapshot(); snapshot.Selected != SelectedDirect || !snapshot.DirectHealthy {
		t.Fatalf("relay loss disturbed the established direct path: %#v", snapshot)
	}
	if direct.closeCount() != 0 {
		t.Fatal("relay loss closed the established direct connection")
	}

	replacement := newRelayRecoveryConnection()
	if err := recovery.ReplaceRelay(replacement); err != nil {
		t.Fatalf("authenticated replacement relay was rejected: %v", err)
	}
	snapshot := mux.Snapshot()
	if !snapshot.RelayHealthy || !snapshot.DirectHealthy || snapshot.Selected != SelectedDirect || snapshot.DirectEpoch != 7 {
		t.Fatalf("relay replacement did not restore a warm fallback without disturbing direct: %#v", snapshot)
	}
	if direct.closeCount() != 0 {
		t.Fatal("relay replacement closed the established direct connection")
	}

	if err := mux.SendPacket([]byte("direct-only while fallback is warm")); err != nil {
		t.Fatal(err)
	}
	if got := direct.sendCount(); got != 1 {
		t.Fatalf("selected direct path sent %d copies, want exactly one", got)
	}
	if got := oldRelay.sendCount(); got != 0 {
		t.Fatalf("retired relay sent %d unexpected copies", got)
	}
	if got := replacement.sendCount(); got != 0 {
		t.Fatalf("warm replacement relay sent %d copies while direct was healthy", got)
	}

	direct.setSendError(net.ErrClosed)
	if err := mux.SendPacket([]byte("one fallback copy")); err != nil {
		t.Fatalf("direct failure did not use the restored warm relay: %v", err)
	}
	snapshot = mux.Snapshot()
	if snapshot.Selected != SelectedRelay || !snapshot.RelayHealthy || snapshot.DirectHealthy {
		t.Fatalf("direct failure did not select the replacement relay: %#v", snapshot)
	}
	if got := oldRelay.sendCount(); got != 0 {
		t.Fatalf("retired relay sent %d fallback copies", got)
	}
	if got := replacement.sendCount(); got != 1 {
		t.Fatalf("replacement relay sent %d fallback copies, want exactly one", got)
	}
}

func TestDelayedRetiredRelayFailureCannotDemoteReplacement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	oldRelay := newRelayRecoveryConnection()
	mux, err := New(ctx, 1200, oldRelay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	direct := newRelayRecoveryConnection()
	if err := mux.ActivateDirect(11, direct); err != nil {
		t.Fatal(err)
	}
	recovery := requireRelayRecovery(t, mux)
	mux.mu.Lock()
	oldID := mux.relay.id
	mux.mu.Unlock()

	replacement := newRelayRecoveryConnection()
	if err := recovery.ReplaceRelay(replacement); err != nil {
		t.Fatal(err)
	}
	mux.mu.Lock()
	replacementID := mux.relay.id
	mux.mu.Unlock()
	if replacementID == oldID {
		t.Fatal("relay replacement reused the retired connection instance ID")
	}
	if oldRelay.closeCount() != 1 {
		t.Fatalf("retired relay close count=%d want=1", oldRelay.closeCount())
	}

	// Model a ReceiveDatagram failure completing after the atomic swap. The
	// callback carries the retired instance ID and must be ignored exactly.
	mux.relayFailed(oldID)
	snapshot := mux.Snapshot()
	if !snapshot.RelayHealthy || !snapshot.DirectHealthy || snapshot.Selected != SelectedDirect {
		t.Fatalf("delayed old-relay failure demoted a replacement: %#v", snapshot)
	}
	select {
	case <-recovery.RelayRecoveryNeeded():
		t.Fatal("stale relay failure scheduled recovery for a healthy replacement")
	default:
	}
	if direct.closeCount() != 0 {
		t.Fatal("stale relay failure closed the established direct path")
	}

	// Prove the replacement is the sole fallback sender. A current direct
	// failure must not revive or duplicate onto the retired relay.
	direct.setSendError(net.ErrClosed)
	if err := mux.SendPacket([]byte("replacement-only fallback")); err != nil {
		t.Fatal(err)
	}
	if got := oldRelay.sendCount(); got != 0 {
		t.Fatalf("retired relay sent %d copies after delayed failure", got)
	}
	if got := replacement.sendCount(); got != 1 {
		t.Fatalf("replacement relay sent %d copies, want exactly one", got)
	}
}

func TestRelayReplacementInstanceIDExhaustionFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	oldRelay := newRelayRecoveryConnection()
	mux, err := New(ctx, 1200, oldRelay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	direct := newRelayRecoveryConnection()
	if err := mux.ActivateDirect(29, direct); err != nil {
		t.Fatal(err)
	}

	mux.mu.Lock()
	mux.nextID = ^uint64(0)
	mux.mu.Unlock()
	replacement := newRelayRecoveryConnection()
	if err := mux.ReplaceRelay(replacement); !errors.Is(err, ErrInstanceIDExhausted) {
		t.Fatalf("instance-ID exhaustion returned %v", err)
	}
	snapshot := mux.Snapshot()
	if !snapshot.RelayHealthy || !snapshot.DirectHealthy || snapshot.Selected != SelectedDirect || snapshot.DirectEpoch != 29 {
		t.Fatalf("failed-closed replacement disturbed current paths: %#v", snapshot)
	}
	if oldRelay.closeCount() != 0 || direct.closeCount() != 0 || replacement.closeCount() != 0 {
		t.Fatal("instance-ID exhaustion closed an existing path or stole ownership of the rejected candidate")
	}
	select {
	case <-mux.RelayRecoveryNeeded():
		t.Fatal("instance-ID exhaustion fabricated a relay-loss event")
	default:
	}
}

func requireRelayRecovery(t *testing.T, mux *Mux) relayRecoveryCapable {
	t.Helper()
	recovery, ok := any(mux).(relayRecoveryCapable)
	if !ok {
		t.Fatal("mux has no relay-recovery signal/replacement contract; a relay outage is permanent until process restart")
	}
	return recovery
}

func waitRelayState(t *testing.T, mux *Mux, healthy bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if mux.Snapshot().RelayHealthy == healthy {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("relay health did not become %t: %#v", healthy, mux.Snapshot())
}

type relayRecoveryReceive struct {
	packet []byte
	err    error
}

// relayRecoveryConnection deliberately does not unblock ReceiveDatagram from
// Close. That permits a deterministic delayed completion from a retired
// instance; the mux context still bounds final test shutdown.
type relayRecoveryConnection struct {
	receive chan relayRecoveryReceive

	mu         sync.Mutex
	sends      [][]byte
	sendErr    error
	closeCalls int
}

func newRelayRecoveryConnection() *relayRecoveryConnection {
	return &relayRecoveryConnection{receive: make(chan relayRecoveryReceive, 4)}
}

func (c *relayRecoveryConnection) SendDatagram(packet []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sendErr != nil {
		return c.sendErr
	}
	c.sends = append(c.sends, append([]byte(nil), packet...))
	return nil
}

func (c *relayRecoveryConnection) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case result := <-c.receive:
		return append([]byte(nil), result.packet...), result.err
	}
}

func (c *relayRecoveryConnection) Close(string) error {
	c.mu.Lock()
	c.closeCalls++
	c.mu.Unlock()
	return nil
}

func (c *relayRecoveryConnection) failReceive(err error) {
	c.receive <- relayRecoveryReceive{err: err}
}

func (c *relayRecoveryConnection) setSendError(err error) {
	c.mu.Lock()
	c.sendErr = err
	c.mu.Unlock()
}

func (c *relayRecoveryConnection) sendCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sends)
}

func (c *relayRecoveryConnection) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeCalls
}
