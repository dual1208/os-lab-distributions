package pathstate

import (
	"testing"
	"time"
)

func TestDirectFailureKeepsRouteOnWarmRelay(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	m := New(7)
	if !m.SetRelayHealth(7, true) || !m.BeginPunch(7, 1) || !m.BeginDirectProbe(7, 1, now) {
		t.Fatal("valid transition rejected")
	}
	if m.ActivateDirect(7, 1, now.Add(29*time.Second), 30*time.Second) {
		t.Fatal("unstable direct path activated")
	}
	if !m.ActivateDirect(7, 1, now.Add(30*time.Second), 30*time.Second) {
		t.Fatal("stable direct path rejected")
	}
	if got := m.Snapshot(); got.State != Direct || !got.RouteUp {
		t.Fatalf("unexpected direct snapshot: %#v", got)
	}
	if !m.DirectFailed(7, 1) {
		t.Fatal("direct failure rejected")
	}
	if got := m.Snapshot(); got.State != RelayReady || !got.RouteUp || got.DirectHealthy {
		t.Fatalf("warm fallback failed: %#v", got)
	}
}

func TestGenerationAndEpochOwnershipRejectStaleEvents(t *testing.T) {
	m := New(4)
	m.SetRelayHealth(4, true)
	if !m.BeginPunch(4, 2) {
		t.Fatal("initial punch rejected")
	}
	m.ReplaceGeneration(5)
	if m.SetRelayHealth(4, true) || m.BeginDirectProbe(4, 2, time.Now()) || m.DirectFailed(4, 2) {
		t.Fatal("stale generation changed state")
	}
	if got := m.Snapshot(); got.Generation != 5 || got.State != Offline || got.RouteUp {
		t.Fatalf("replacement did not fail closed: %#v", got)
	}
	if !m.SetRelayHealth(5, true) || !m.BeginPunch(5, 3) {
		t.Fatal("new generation rejected")
	}
	if m.BeginPunch(5, 2) || m.DirectFailed(5, 2) {
		t.Fatal("stale path epoch changed state")
	}
}

func TestHealthyDirectSurvivesRelayLoss(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	m := New(1)
	m.SetRelayHealth(1, true)
	m.BeginPunch(1, 1)
	m.BeginDirectProbe(1, 1, now)
	if !m.ActivateDirect(1, 1, now, 0) {
		t.Fatal("direct activation rejected")
	}
	m.SetRelayHealth(1, false)
	if got := m.Snapshot(); got.State != Direct || !got.RouteUp || got.RelayHealthy {
		t.Fatalf("relay loss destroyed direct path: %#v", got)
	}
}

func TestRepunchIsMakeBeforeBreak(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	m := New(1)
	m.SetRelayHealth(1, true)
	m.BeginPunch(1, 1)
	m.BeginDirectProbe(1, 1, now)
	m.ActivateDirect(1, 1, now, 0)

	if !m.BeginPunch(1, 2) {
		t.Fatal("new direct candidate rejected")
	}
	got := m.Snapshot()
	if got.State != Direct || got.Attempt != Punching || !got.DirectHealthy || !got.RouteUp || got.ActiveEpoch != 1 || got.AttemptEpoch != 2 {
		t.Fatalf("new attempt disturbed active path: %#v", got)
	}
	if !m.DirectFailed(1, 2) {
		t.Fatal("candidate failure rejected")
	}
	got = m.Snapshot()
	if got.State != Direct || got.Attempt != Offline || !got.DirectHealthy || got.ActiveEpoch != 1 {
		t.Fatalf("failed candidate broke active path: %#v", got)
	}
}
