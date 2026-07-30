package edge

import (
	"context"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/datapath"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
)

func TestUnselectedRelayIdentityCannotOverwriteSelectedDirectStatus(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	current := identity.Verified{NotAfter: expiry, PinSlot: 0}
	next := identity.Verified{NotAfter: expiry.Add(time.Hour), PinSlot: 1}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	direct, _ := newControlSurvivalConnectionPair()
	if err := mux.ActivateDirect(41, direct); err != nil {
		t.Fatal(err)
	}
	snapshot := mux.Snapshot()
	runner := &Runner{localData: current, pathPeerData: map[pathIdentityKey]identity.Verified{
		{mux: mux, path: datapath.SelectedRelay, instanceID: snapshot.RelayInstanceID}:   next,
		{mux: mux, path: datapath.SelectedDirect, instanceID: snapshot.DirectInstanceID}: current,
	}}

	peer := selectedPeerData(mux, snapshot, runner.pathPeerData)
	status := selectedDataIdentityStatus(runner.localData, peer, pathStatus(snapshot, "active"))
	if status == nil || status.Peer == nil || status.Peer.PinSlot != "current" ||
		status.Path != string(datapath.SelectedDirect) || status.DirectEpoch != 41 {
		t.Fatalf("selected direct identity was overwritten by warm relay: %#v", status)
	}

	replacement, _ := newControlSurvivalConnectionPair()
	relayID, err := mux.ReplaceRelayWithInstance(replacement)
	if err != nil {
		t.Fatal(err)
	}
	runner.setRelayPeerData(mux, identity.Verified{NotAfter: expiry.Add(2 * time.Hour), PinSlot: 1}, relayID)
	snapshot = mux.Snapshot()
	peer = selectedPeerData(mux, snapshot, runner.pathPeerData)
	status = selectedDataIdentityStatus(runner.localData, peer, pathStatus(snapshot, "active"))
	if status == nil || status.Peer == nil || status.Peer.PinSlot != "current" {
		t.Fatalf("unselected replacement relay changed direct status: %#v", status)
	}
}

func TestRelayIdentityReplacementInterleavingsFailClosed(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	oldIdentity := identity.Verified{NotAfter: expiry, PinSlot: 0}
	newIdentity := identity.Verified{NotAfter: expiry.Add(time.Hour), PinSlot: 1}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	oldRelay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(ctx, 1200, oldRelay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	oldSnapshot := mux.Snapshot()
	oldBinding := map[pathIdentityKey]identity.Verified{
		{mux: mux, path: datapath.SelectedRelay, instanceID: oldSnapshot.RelayInstanceID}: oldIdentity,
	}

	futureBinding := map[pathIdentityKey]identity.Verified{
		{mux: mux, path: datapath.SelectedRelay, instanceID: oldSnapshot.RelayInstanceID + 1}: newIdentity,
	}
	if got := selectedPeerData(mux, oldSnapshot, futureBinding); !got.NotAfter.IsZero() {
		t.Fatalf("future relay identity was attributed to retired instance: %#v", got)
	}

	replacement, _ := newControlSurvivalConnectionPair()
	newID, err := mux.ReplaceRelayWithInstance(replacement)
	if err != nil {
		t.Fatal(err)
	}
	newSnapshot := mux.Snapshot()
	if newID == oldSnapshot.RelayInstanceID || newID != newSnapshot.RelayInstanceID {
		t.Fatalf("relay replacement reused or lost its exact ID: old=%d new=%d snapshot=%d", oldSnapshot.RelayInstanceID, newID, newSnapshot.RelayInstanceID)
	}
	if got := selectedPeerData(mux, newSnapshot, oldBinding); !got.NotAfter.IsZero() {
		t.Fatalf("retired relay identity was attributed to replacement: %#v", got)
	}
	newBinding := map[pathIdentityKey]identity.Verified{
		{mux: mux, path: datapath.SelectedRelay, instanceID: newID}: newIdentity,
	}
	if got := selectedPeerData(mux, newSnapshot, newBinding); !got.NotAfter.Equal(newIdentity.NotAfter) {
		t.Fatalf("exact replacement relay identity was not published: %#v", got)
	}
}

func TestSameEpochDirectReplacementCannotReuseRetiredIdentity(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	oldIdentity := identity.Verified{NotAfter: expiry, PinSlot: 0}
	newIdentity := identity.Verified{NotAfter: expiry.Add(time.Hour), PinSlot: 1}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	oldDirect, _ := newControlSurvivalConnectionPair()
	if err := mux.ActivateDirect(73, oldDirect); err != nil {
		t.Fatal(err)
	}
	oldSnapshot := mux.Snapshot()
	oldBinding := map[pathIdentityKey]identity.Verified{
		{mux: mux, path: datapath.SelectedDirect, instanceID: oldSnapshot.DirectInstanceID}: oldIdentity,
	}
	if !mux.DirectFailed(73) {
		t.Fatal("old direct instance did not fail")
	}
	replacement, _ := newControlSurvivalConnectionPair()
	newID, err := mux.PrepareDirectWithInstance(73, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.SelectDirect(73); err != nil {
		t.Fatal(err)
	}
	if err := mux.CommitDirect(73); err != nil {
		t.Fatal(err)
	}
	newSnapshot := mux.Snapshot()
	if newSnapshot.DirectEpoch != oldSnapshot.DirectEpoch || newID == oldSnapshot.DirectInstanceID {
		t.Fatalf("test did not create distinct same-epoch instances: old=%#v new=%#v", oldSnapshot, newSnapshot)
	}
	if got := selectedPeerData(mux, newSnapshot, oldBinding); !got.NotAfter.IsZero() {
		t.Fatalf("same epoch reused retired direct identity: %#v", got)
	}
	newBinding := map[pathIdentityKey]identity.Verified{
		{mux: mux, path: datapath.SelectedDirect, instanceID: newID}: newIdentity,
	}
	if got := selectedPeerData(mux, newSnapshot, newBinding); !got.NotAfter.Equal(newIdentity.NotAfter) {
		t.Fatalf("exact replacement direct identity was not published: %#v", got)
	}
}

func TestDataPeerStatusRequiresExactHealthySelectedMuxInstance(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	verified := identity.Verified{NotAfter: expiry, PinSlot: 0}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(ctx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	snapshot := mux.Snapshot()
	valid := map[pathIdentityKey]identity.Verified{
		{mux: mux, path: datapath.SelectedRelay, instanceID: snapshot.RelayInstanceID}: verified,
	}

	wrongMuxRelay, _ := newControlSurvivalConnectionPair()
	wrongMux, err := datapath.New(ctx, 1200, wrongMuxRelay)
	if err != nil {
		t.Fatal(err)
	}
	defer wrongMux.Close()
	for name, binding := range map[string]map[pathIdentityKey]identity.Verified{
		"zero instance": {
			{mux: mux, path: datapath.SelectedRelay}: verified,
		},
		"wrong instance": {
			{mux: mux, path: datapath.SelectedRelay, instanceID: snapshot.RelayInstanceID + 1}: verified,
		},
		"wrong mux lifetime": {
			{mux: wrongMux, path: datapath.SelectedRelay, instanceID: snapshot.RelayInstanceID}: verified,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := selectedPeerData(mux, snapshot, binding); !got.NotAfter.IsZero() {
				t.Fatalf("unbound path exposed peer identity: %#v", got)
			}
		})
	}
	if got := selectedPeerData(mux, snapshot, valid); !got.NotAfter.Equal(verified.NotAfter) {
		t.Fatalf("healthy selected relay did not expose its exact identity: %#v", got)
	}
}
