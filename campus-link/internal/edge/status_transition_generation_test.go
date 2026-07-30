package edge

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/datapath"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
)

func readEdgeStatusState(t *testing.T, path string) edgeState {
	t.Helper()
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var status edgeState
	if err := json.Unmarshal(wire, &status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestStatusPublicationAndIdentityTransitionGenerationsAreSticky(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge.json")
	expiry := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	current := identity.Verified{NotAfter: expiry, PinSlot: 0}
	next := identity.Verified{NotAfter: expiry.Add(time.Hour), PinSlot: 1}
	runner := &Runner{
		cfg:          config.Edge{StatusPath: path},
		state:        edgeState{Site: "site-a", Path: edgePathStatus{DirectRequired: true}},
		localControl: current,
		peerControl:  current,
	}
	if err := runner.writeStatusNow(); err != nil {
		t.Fatal(err)
	}
	baseline := readEdgeStatusState(t, path)
	if baseline.StatusGeneration == 0 {
		t.Fatal("baseline status publication generation is zero")
	}

	// Both writes are synchronous in this fixture. The public identity returns
	// to the exact baseline view, while the sticky counter retains the toggle.
	runner.setPeerControl(next)
	runner.setPeerControl(current)
	final := readEdgeStatusState(t, path)
	if final.StatusGeneration != baseline.StatusGeneration+2 {
		t.Fatalf(
			"status generation=%d want=%d",
			final.StatusGeneration, baseline.StatusGeneration+2,
		)
	}
	if final.IdentityTransitions != baseline.IdentityTransitions+2 {
		t.Fatalf(
			"identity transitions=%d want=%d",
			final.IdentityTransitions, baseline.IdentityTransitions+2,
		)
	}
	if final.ControlIdentity == nil || final.ControlIdentity.Peer == nil ||
		final.ControlIdentity.Peer.Expires != baseline.ControlIdentity.Peer.Expires ||
		final.ControlIdentity.Peer.PinSlot != baseline.ControlIdentity.Peer.PinSlot {
		t.Fatalf("public identity did not return to its baseline view: %#v", final.ControlIdentity)
	}
}

func TestStatusPathTransitionsSurviveUnpublishedDirectRoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.NewDirectRequired(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	direct, _ := newControlSurvivalConnectionPair()
	if err := mux.ActivateDirect(31, direct); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "edge.json")
	runner := &Runner{
		cfg:     config.Edge{StatusPath: path},
		state:   edgeState{Site: "site-a", Path: edgePathStatus{DirectRequired: true}},
		pathMux: mux,
	}
	if err := runner.writeStatusNow(); err != nil {
		t.Fatal(err)
	}
	baseline := readEdgeStatusState(t, path)

	// No edge status is published while the selected path goes direct -> none
	// -> direct. The mux's cumulative generation must survive that coalescing.
	if !mux.DirectFailed(31) {
		t.Fatal("direct path was not withdrawn")
	}
	replacement, _ := newControlSurvivalConnectionPair()
	if err := mux.ActivateDirect(31, replacement); err != nil {
		t.Fatal(err)
	}
	if err := runner.writeStatusNow(); err != nil {
		t.Fatal(err)
	}
	final := readEdgeStatusState(t, path)
	if final.Path.Selected != string(datapath.SelectedDirect) || !final.Path.DirectHealthy {
		t.Fatalf("final path is not direct: %#v", final.Path)
	}
	if final.SelectedPathTransitions != baseline.SelectedPathTransitions+2 {
		t.Fatalf(
			"selected path transitions=%d want=%d",
			final.SelectedPathTransitions, baseline.SelectedPathTransitions+2,
		)
	}
	if final.IdentityTransitions != baseline.IdentityTransitions+2 {
		t.Fatalf(
			"selected data binding transitions=%d want=%d",
			final.IdentityTransitions, baseline.IdentityTransitions+2,
		)
	}
}

func TestStatusWriterAndSynchronousIdentityAccountingDoNotInvertLocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge.json")
	expiry := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	current := identity.Verified{NotAfter: expiry, PinSlot: 0}
	next := identity.Verified{NotAfter: expiry.Add(time.Hour), PinSlot: 1}
	runner := &Runner{
		cfg:          config.Edge{StatusPath: path},
		statusWake:   make(chan struct{}, 1),
		state:        edgeState{Site: "site-a", Path: edgePathStatus{DirectRequired: true}},
		localControl: current,
		peerControl:  current,
	}
	if err := runner.writeStatusNow(); err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		for index := 0; index < 100; index++ {
			if index%2 == 0 {
				runner.setPeerControl(next)
			} else {
				runner.setPeerControl(current)
			}
		}
	}()
	go func() {
		defer wait.Done()
		for index := 0; index < 100; index++ {
			if err := runner.writeStatusNow(); err != nil {
				t.Errorf("status write %d: %v", index, err)
				return
			}
		}
	}()
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("status writer and synchronous identity accounting deadlocked")
	}
	if err := runner.writeStatusNow(); err != nil {
		t.Fatal(err)
	}
	final := readEdgeStatusState(t, path)
	if final.StatusGeneration == 0 || final.IdentityTransitions == 0 {
		t.Fatalf("concurrent status evidence did not advance: %#v", final)
	}
}

func TestSelectedDataIdentityToggleAndRevertIsStickyWithoutStatusWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	direct, _ := newControlSurvivalConnectionPair()
	if err := mux.ActivateDirect(71, direct); err != nil {
		t.Fatal(err)
	}
	snapshot := mux.Snapshot()
	expiry := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	current := identity.Verified{NotAfter: expiry, PinSlot: 0}
	next := identity.Verified{NotAfter: expiry.Add(time.Hour), PinSlot: 1}
	directKey := pathIdentityKey{
		mux: mux, path: datapath.SelectedDirect, instanceID: snapshot.DirectInstanceID,
	}
	runner := &Runner{
		state:        edgeState{Path: edgePathStatus{DirectRequired: true}},
		localData:    current,
		pathMux:      mux,
		pathSnapshot: snapshot,
		pathPeerData: map[pathIdentityKey]identity.Verified{directKey: current},
	}
	runner.mu.Lock()
	runner.refreshStatusTransitionsLocked()
	baseline := runner.identityTransitions
	runner.bindPathIdentityLocked(
		mux, datapath.SelectedDirect, snapshot.DirectInstanceID, next,
	)
	runner.bindPathIdentityLocked(
		mux, datapath.SelectedDirect, snapshot.DirectInstanceID, current,
	)
	if runner.identityTransitions != baseline+2 {
		t.Fatalf(
			"selected identity transitions=%d want=%d",
			runner.identityTransitions, baseline+2,
		)
	}
	beforeWarmRelay := runner.identityTransitions
	runner.bindPathIdentityLocked(
		mux, datapath.SelectedRelay, snapshot.RelayInstanceID, next,
	)
	if runner.identityTransitions != beforeWarmRelay {
		t.Fatalf("unselected relay identity changed selected evidence: %d -> %d", beforeWarmRelay, runner.identityTransitions)
	}
	runner.mu.Unlock()
}
