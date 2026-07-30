package edge

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/datapath"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
)

func TestDirectActivationCannotPrepareWithoutArmedCutoffGuard(t *testing.T) {
	runner, lease, mux, candidate, cleanup := newCutoffActivationFixture(t, 81)
	defer cleanup()
	activation := &muxActivation{
		runner: runner, mux: mux, connection: candidate, epoch: 81, lease: lease,
		cutoff: time.Now().Add(time.Hour),
	}
	if err := activation.PrepareDirect(81); !errors.Is(err, identity.ErrCertificateCutoff) {
		t.Fatalf("unguarded direct candidate was not rejected: %v", err)
	}
	if snapshot := mux.Snapshot(); snapshot.Selected != datapath.SelectedRelay || snapshot.DirectInstanceID != 0 {
		t.Fatalf("unguarded candidate reached the mux: %#v", snapshot)
	}
}

func TestDirectCutoffWinningAfterPreparePreventsSelection(t *testing.T) {
	runner, lease, mux, candidate, cleanup := newCutoffActivationFixture(t, 82)
	defer cleanup()
	cutoff := time.Now().Add(time.Hour)
	activation, stop := armTestMuxActivation(t, runner, lease, mux, candidate, 82, cutoff)
	defer stop()
	if err := activation.PrepareDirect(82); err != nil {
		t.Fatal(err)
	}

	// Force the guard callback between preparation and selection. Its expired
	// decision is serialized through Runner.mu with every activation phase.
	activation.expireCutoff()
	if err := activation.SelectDirect(82); !errors.Is(err, identity.ErrCertificateCutoff) {
		t.Fatalf("cutoff-lost selection returned %v", err)
	}
	if snapshot := mux.Snapshot(); snapshot.Selected != datapath.SelectedRelay || snapshot.DirectHealthy {
		t.Fatalf("expired prepared candidate became selected: %#v", snapshot)
	}
}

func TestDirectCommitPerformsFinalSerializedWallCutoffRecheck(t *testing.T) {
	runner, lease, mux, candidate, cleanup := newCutoffActivationFixture(t, 83)
	defer cleanup()
	cutoff := time.Now().Add(time.Hour)
	observed := cutoff.Add(-time.Second)
	activation, stop := armTestMuxActivation(t, runner, lease, mux, candidate, 83, cutoff)
	defer stop()
	activation.now = func() time.Time { return observed }
	if err := activation.PrepareDirect(83); err != nil {
		t.Fatal(err)
	}
	if err := activation.SelectDirect(83); err != nil {
		t.Fatal(err)
	}
	if snapshot := mux.Snapshot(); snapshot.Selected != datapath.SelectedDirect {
		t.Fatalf("test did not reach rollback-capable selection: %#v", snapshot)
	}

	// Advance only the activation's wall observation, deterministically forcing
	// expiry after selection but before the irreversible commit phase.
	observed = cutoff
	if err := activation.CommitDirect(83); !errors.Is(err, identity.ErrCertificateCutoff) {
		t.Fatalf("final cutoff recheck returned %v", err)
	}
	if snapshot := mux.Snapshot(); snapshot.Selected != datapath.SelectedRelay || snapshot.DirectHealthy {
		t.Fatalf("expired direct candidate survived final commit check: %#v", snapshot)
	}
}

func TestDirectPreparePublishesExactIdentityBeforeSelection(t *testing.T) {
	runner, lease, mux, candidate, cleanup := newCutoffActivationFixture(t, 84)
	defer cleanup()
	cutoff := time.Now().Add(time.Hour)
	activation, stop := armTestMuxActivation(t, runner, lease, mux, candidate, 84, cutoff)
	defer stop()
	activation.peerData = identity.Verified{NotAfter: cutoff.Add(time.Hour), PinSlot: 1}
	runner.mu.Lock()
	runner.pathMux = mux
	runner.mu.Unlock()
	if err := activation.PrepareDirect(84); err != nil {
		t.Fatal(err)
	}

	runner.mu.Lock()
	preparedSnapshot := mux.Snapshot()
	_, preparedBound := runner.pathPeerData[pathIdentityKey{
		mux: mux, path: datapath.SelectedDirect, instanceID: activation.instanceID,
	}]
	runner.mu.Unlock()
	if preparedSnapshot.Selected != datapath.SelectedRelay || !preparedBound {
		t.Fatalf("future direct identity was not bound before selection: snapshot=%#v bound=%t", preparedSnapshot, preparedBound)
	}
	if err := activation.SelectDirect(84); err != nil {
		t.Fatal(err)
	}

	// Status uses this exact Runner->Mux lock order, so the first selected
	// snapshot must resolve the already-published identity.
	runner.mu.Lock()
	selectedSnapshot := mux.Snapshot()
	peer := selectedPeerData(mux, selectedSnapshot, runner.pathPeerData)
	runner.mu.Unlock()
	if selectedSnapshot.Selected != datapath.SelectedDirect || peer.PinSlot != activation.peerData.PinSlot ||
		!peer.NotAfter.Equal(activation.peerData.NotAfter) {
		t.Fatalf("selected direct path lacked its exact identity: snapshot=%#v peer=%#v", selectedSnapshot, peer)
	}
	if err := activation.CommitDirect(84); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	bindingCount := len(runner.pathPeerData)
	runner.mu.Unlock()
	if bindingCount != 1 {
		t.Fatalf("committed direct path retained unbounded identities: %d", bindingCount)
	}
}

func armTestMuxActivation(
	t *testing.T,
	runner *Runner,
	lease planSessionLease,
	mux *datapath.Mux,
	connection datapath.Connection,
	epoch uint64,
	cutoff time.Time,
) (*muxActivation, func()) {
	t.Helper()
	activation := &muxActivation{
		runner: runner, mux: mux, connection: connection, epoch: epoch, lease: lease, cutoff: cutoff,
	}
	guard, err := identity.GuardCertificateCutoff(context.Background(), cutoff, activation.expireCutoff)
	if err != nil {
		t.Fatal(err)
	}
	activation.cutoffGuard = guard
	return activation, guard.Stop
}

func newCutoffActivationFixture(
	t *testing.T, epoch uint64,
) (*Runner, planSessionLease, *datapath.Mux, datapath.Connection, func()) {
	t.Helper()
	runner := controlSurvivalRunner()
	lease := runner.beginPlanSession(edgeTestRelayGeneration)
	if !lease.valid() {
		t.Fatal("test plan lease unavailable")
	}
	runner.planEpoch.Store(epoch)
	ctx, cancel := context.WithCancel(context.Background())
	relay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(ctx, 1200, relay)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	candidate, _ := newControlSurvivalConnectionPair()
	return runner, lease, mux, candidate, func() {
		mux.Close()
		cancel()
		runner.endPlanSession(lease)
	}
}
