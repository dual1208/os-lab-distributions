package datapath

import (
	"context"
	"testing"
)

func TestRetireDirectClearsExactInstancesAndPermitsFreshEpochNamespace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, _ := connectionPair()
	mux, err := New(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	first, _ := connectionPair()
	if err := mux.ActivateDirect(17, first); err != nil {
		t.Fatal(err)
	}
	mux.mu.Lock()
	firstID := mux.direct.id
	mux.mu.Unlock()
	if !mux.directFailed(17, firstID) {
		t.Fatal("exact first direct instance did not fail")
	}

	retry, _ := connectionPair()
	if err := mux.ActivateDirect(17, retry); err != nil {
		t.Fatal(err)
	}
	mux.mu.Lock()
	retryID := mux.direct.id
	mux.mu.Unlock()
	if mux.DirectFailed(17) {
		t.Fatal("epoch-only failure demoted a healthy same-epoch replacement")
	}
	pending, _ := connectionPair()
	if err := mux.PrepareDirect(18, pending); err != nil {
		t.Fatal(err)
	}

	if !mux.RetireDirect() {
		t.Fatal("open mux refused atomic direct retirement")
	}
	snapshot := mux.Snapshot()
	if snapshot.DirectHealthy || snapshot.DirectEpoch != 0 || !snapshot.RelayHealthy || snapshot.Selected != SelectedRelay {
		t.Fatalf("direct authority state survived retirement: %#v", snapshot)
	}
	for name, connection := range map[string]*fakeConnection{"retry": retry, "pending": pending} {
		select {
		case <-connection.closed:
		default:
			t.Fatalf("%s direct instance remained open after retirement", name)
		}
	}

	fresh, _ := connectionPair()
	if err := mux.ActivateDirect(1, fresh); err != nil {
		t.Fatalf("fresh namespace could not restart at epoch one: %v", err)
	}
	if mux.directFailed(17, retryID) {
		t.Fatal("delayed retired-instance failure demoted the fresh namespace")
	}
	snapshot = mux.Snapshot()
	if !snapshot.DirectHealthy || snapshot.DirectEpoch != 1 || snapshot.Selected != SelectedDirect {
		t.Fatalf("fresh direct path was not preserved: %#v", snapshot)
	}
}
