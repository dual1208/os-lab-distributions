package datapath

import (
	"context"
	"testing"
	"time"
)

func TestSelectedPathTransitionsSurviveCoalescedDirectRoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := NewDirectRequired(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	_, first := connectionPair()
	if err := mux.ActivateDirect(17, first); err != nil {
		t.Fatal(err)
	}
	baseline := mux.Snapshot()
	if baseline.Selected != SelectedDirect || baseline.SelectedPathTransitions == 0 {
		t.Fatalf("direct baseline lacks a path transition generation: %#v", baseline)
	}

	// Do not consume Changes between transitions. The one-slot notification
	// channel may coalesce snapshots, but the cumulative counter must retain
	// direct -> none -> direct.
	if !mux.DirectFailed(17) {
		t.Fatal("direct path was not withdrawn")
	}
	_, replacement := connectionPair()
	if err := mux.ActivateDirect(17, replacement); err != nil {
		t.Fatal(err)
	}
	final := mux.Snapshot()
	if final.Selected != SelectedDirect || !final.DirectHealthy {
		t.Fatalf("replacement direct path is not healthy: %#v", final)
	}
	if final.SelectedPathTransitions != baseline.SelectedPathTransitions+2 {
		t.Fatalf(
			"coalesced direct round trip transitions=%d want=%d",
			final.SelectedPathTransitions, baseline.SelectedPathTransitions+2,
		)
	}
}

func TestSelectedPathTransitionsSurviveRelayRoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := New(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	_, first := connectionPair()
	if err := mux.ActivateDirect(23, first); err != nil {
		t.Fatal(err)
	}
	baseline := mux.Snapshot()
	if !mux.DirectFailed(23) {
		t.Fatal("direct path was not returned to relay")
	}
	_, replacement := connectionPair()
	if err := mux.ActivateDirect(23, replacement); err != nil {
		t.Fatal(err)
	}
	final := mux.Snapshot()
	if final.Selected != SelectedDirect || final.SelectedPathTransitions != baseline.SelectedPathTransitions+2 {
		t.Fatalf("relay round trip was not sticky: baseline=%#v final=%#v", baseline, final)
	}
}

func TestSelectedPathTransitionExhaustionSaturates(t *testing.T) {
	mux := &Mux{
		relay:            pathSlot{id: 1, healthy: true},
		direct:           pathSlot{epoch: 9, id: 2, healthy: true},
		selected:         SelectedRelay,
		pathAuthority:    selectedPathAuthority{selected: SelectedRelay, id: 1},
		pathAuthoritySet: true,
	}
	mux.pathTransitions.Store(^uint64(0) - 1)
	mux.setSelectedLocked(SelectedDirect)
	if got := mux.pathTransitions.Load(); got != ^uint64(0) {
		t.Fatalf("transition counter=%d want saturation", got)
	}
	mux.setSelectedLocked(SelectedRelay)
	if got := mux.pathTransitions.Load(); got != ^uint64(0) {
		t.Fatalf("saturated transition counter wrapped to %d", got)
	}
}

func TestSameSelectedAuthoritiesStillAdvanceTransitionGeneration(t *testing.T) {
	t.Run("direct replacement", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, relay := connectionPair()
		mux, err := NewDirectRequired(ctx, 1200, relay)
		if err != nil {
			t.Fatal(err)
		}
		defer mux.Close()
		_, original := connectionPair()
		if err := mux.ActivateDirect(41, original); err != nil {
			t.Fatal(err)
		}
		baseline := mux.Snapshot()
		_, replacement := connectionPair()
		if _, err := mux.PrepareDirectWithInstance(42, replacement); err != nil {
			t.Fatal(err)
		}
		if err := mux.SelectDirect(42); err != nil {
			t.Fatal(err)
		}
		if err := mux.CommitDirect(42); err != nil {
			t.Fatal(err)
		}
		final := mux.Snapshot()
		if final.Selected != SelectedDirect || final.DirectEpoch != 42 ||
			final.SelectedPathTransitions != baseline.SelectedPathTransitions+1 {
			t.Fatalf("same-enum direct replacement was not counted: baseline=%#v final=%#v", baseline, final)
		}
	})

	t.Run("relay replacement", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, relay := connectionPair()
		mux, err := New(ctx, 1200, relay)
		if err != nil {
			t.Fatal(err)
		}
		defer mux.Close()
		baseline := mux.Snapshot()
		_, replacement := connectionPair()
		if err := mux.ReplaceRelay(replacement); err != nil {
			t.Fatal(err)
		}
		final := mux.Snapshot()
		if final.Selected != SelectedRelay ||
			final.SelectedPathTransitions != baseline.SelectedPathTransitions+1 {
			t.Fatalf("same-enum relay replacement was not counted: baseline=%#v final=%#v", baseline, final)
		}
	})
}

func TestSelectedDirectReplacementAndRollbackRetainBothTransitions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := New(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	_, original := connectionPair()
	if err := mux.ActivateDirect(51, original); err != nil {
		t.Fatal(err)
	}
	baseline := mux.Snapshot()
	_, replacement := connectionPair()
	if _, err := mux.PrepareDirectWithInstance(52, replacement); err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(52); err != nil {
		t.Fatal(err)
	}
	mux.AbortDirect(52)
	final := mux.Snapshot()
	if final.Selected != SelectedDirect || final.DirectEpoch != 51 ||
		final.SelectedPathTransitions != baseline.SelectedPathTransitions+2 {
		t.Fatalf("direct replacement rollback was not sticky: baseline=%#v final=%#v", baseline, final)
	}
}

func TestSelectedPathTransitionsSurviveConcurrentNotifyCoalescing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, relay := connectionPair()
	mux, err := NewDirectRequired(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	_, original := connectionPair()
	if err := mux.ActivateDirect(61, original); err != nil {
		t.Fatal(err)
	}
	_, replacement := connectionPair()
	if _, err := mux.PrepareDirectWithInstance(62, replacement); err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(62); err != nil {
		t.Fatal(err)
	}
	baseline := mux.Snapshot()

	// Hold notification publication so both committed mutations complete under
	// Mux.mu before either notify can sample. Counting in notify would collapse
	// the none -> direct round trip into the final direct state.
	mux.notifyMu.Lock()
	failure := make(chan bool, 1)
	go func() { failure <- mux.DirectFailed(61) }()
	waitSelectedPath(t, mux, SelectedNone, 61)
	commit := make(chan error, 1)
	go func() { commit <- mux.CommitDirect(62) }()
	waitSelectedPath(t, mux, SelectedDirect, 62)
	mux.notifyMu.Unlock()
	if !<-failure {
		t.Fatal("old direct path was not withdrawn")
	}
	if err := <-commit; err != nil {
		t.Fatal(err)
	}
	final := mux.Snapshot()
	if final.SelectedPathTransitions != baseline.SelectedPathTransitions+2 {
		t.Fatalf("concurrent notification coalescing lost transitions: baseline=%#v final=%#v", baseline, final)
	}
}

func waitSelectedPath(t *testing.T, mux *Mux, selected Selected, epoch uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		snapshot := mux.Snapshot()
		if snapshot.Selected == selected && (selected != SelectedDirect || snapshot.DirectEpoch == epoch) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("selected path did not become %s at epoch %d: %#v", selected, epoch, mux.Snapshot())
}
