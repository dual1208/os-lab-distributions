package datapath

import (
	"context"
	"errors"
	"testing"
)

func TestSameEpochRetryReplacesOnlyUnhealthyDirect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := New(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	_, original := connectionPair()
	if err := mux.ActivateDirect(17, original); err != nil {
		t.Fatal(err)
	}
	_, whileHealthy := connectionPair()
	if err := mux.PrepareDirect(17, whileHealthy); !errors.Is(err, ErrStalePath) {
		t.Fatalf("same-epoch retry replaced a healthy direct path: %v", err)
	}
	_ = whileHealthy.Close("healthy path retained")

	if !mux.DirectFailed(17) {
		t.Fatal("current direct path was not marked unhealthy")
	}
	_, replacement := connectionPair()
	if err := mux.ActivateDirect(17, replacement); err != nil {
		t.Fatalf("same-epoch retry could not replace an unhealthy direct path: %v", err)
	}
	if snapshot := mux.Snapshot(); snapshot.Selected != SelectedDirect || !snapshot.DirectHealthy || snapshot.DirectEpoch != 17 {
		t.Fatalf("same-epoch replacement did not become healthy: %#v", snapshot)
	}
}

func TestDelayedOldInstanceFailuresCannotDemoteSameEpochReplacement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := New(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	_, original := connectionPair()
	if err := mux.ActivateDirect(23, original); err != nil {
		t.Fatal(err)
	}
	mux.mu.Lock()
	oldID := mux.direct.id
	mux.mu.Unlock()
	if !mux.DirectFailed(23) {
		t.Fatal("current direct path was not marked unhealthy")
	}
	_, replacement := connectionPair()
	if err := mux.ActivateDirect(23, replacement); err != nil {
		t.Fatalf("same-epoch replacement failed: %v", err)
	}
	mux.mu.Lock()
	newID := mux.direct.id
	mux.mu.Unlock()
	if oldID == newID {
		t.Fatal("same-epoch replacement reused a connection instance ID")
	}

	// Receive failures already carry an instance ID. A delayed receive failure
	// from the retired connection must be ignored.
	mux.directReceiveFailed(23, oldID)
	if snapshot := mux.Snapshot(); snapshot.Selected != SelectedDirect || !snapshot.DirectHealthy || snapshot.DirectEpoch != 23 {
		t.Fatalf("old receive failure demoted same-epoch replacement: %#v", snapshot)
	}
	// The legacy epoch-only send-failure signal is ambiguous after a retry. It
	// must not be allowed to demote the replacement; current send failures need
	// to use the selected slot's connection instance ID instead.
	if mux.DirectFailed(23) {
		t.Fatal("ambiguous delayed send failure demoted same-epoch replacement")
	}
	if snapshot := mux.Snapshot(); snapshot.Selected != SelectedDirect || !snapshot.DirectHealthy || snapshot.DirectEpoch != 23 {
		t.Fatalf("same-epoch replacement changed after delayed failures: %#v", snapshot)
	}

	// A failure carrying the replacement's actual instance ID must still
	// demote it, proving that stale suppression does not hide current failures.
	mux.directReceiveFailed(23, newID)
	if snapshot := mux.Snapshot(); snapshot.Selected != SelectedRelay || snapshot.DirectHealthy {
		t.Fatalf("current replacement failure was ignored: %#v", snapshot)
	}
}
