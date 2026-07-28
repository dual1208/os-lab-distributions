package relay

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
)

func TestLatestControlSessionExclusivelyOwnsLeg(t *testing.T) {
	s, err := New(config.Relay{Circuit: "c", Prefixes: map[string]string{"site-a": "10.81.0.0/24", "site-b": "10.82.0.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	oldClient, oldServer := net.Pipe()
	defer oldClient.Close()
	defer oldServer.Close()
	newClient, newServer := net.Pipe()
	defer newClient.Close()
	defer newServer.Close()
	oldOwner := s.activateLegLocked("site-a", "same-generation", []byte("old"), oldServer)
	newOwner := s.activateLegLocked("site-a", "same-generation", []byte("new"), newServer)
	if s.clearLegLocked("site-a", oldOwner) {
		t.Fatal("stale handler cleared the replacement session")
	}
	if !s.legs["site-a"].online || s.legs["site-a"].owner != newOwner {
		t.Fatal("replacement session lost ownership")
	}
	if !s.clearLegLocked("site-a", newOwner) || s.legs["site-a"].online {
		t.Fatal("current handler did not clear its session")
	}
	s.mu.Unlock()
}

func TestEstablishedCircuitInvalidatesBothLegsTogether(t *testing.T) {
	s, err := New(config.Relay{Circuit: "c", Prefixes: map[string]string{"site-a": "10.81.0.0/24", "site-b": "10.82.0.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	aClient, aServer := net.Pipe()
	defer aClient.Close()
	defer aServer.Close()
	bClient, bServer := net.Pipe()
	defer bClient.Close()
	defer bServer.Close()
	s.mu.Lock()
	aOwner := s.activateLegLocked("site-a", "g", []byte("a"), aServer)
	s.activateLegLocked("site-b", "g", []byte("b"), bServer)
	if !s.established {
		t.Fatal("two authenticated legs did not establish the circuit")
	}
	if !s.clearLegLocked("site-a", aOwner) {
		t.Fatal("current site owner was not cleared")
	}
	if s.legs["site-a"].online || s.legs["site-b"].online || s.established {
		t.Fatal("peer leg survived an established circuit member loss")
	}
	s.mu.Unlock()
}

func TestOuterDatagramLimitIsBounded(t *testing.T) {
	if maxOuterDatagramSize < 1280 || maxOuterDatagramSize > 4096 {
		t.Fatalf("unexpected outer datagram limit: %d", maxOuterDatagramSize)
	}
}

func TestRelayPlannerScopesCandidatesToCurrentOwners(t *testing.T) {
	s, err := New(config.Relay{Circuit: "c", Prefixes: map[string]string{"site-a": "10.81.0.0/24", "site-b": "10.82.0.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	aClient, aServer := net.Pipe()
	defer aClient.Close()
	defer aServer.Close()
	bClient, bServer := net.Pipe()
	defer bClient.Close()
	defer bServer.Close()
	s.mu.Lock()
	aOwner := s.activateLegLocked("site-a", "ga", []byte("a"), aServer)
	bOwner := s.activateLegLocked("site-b", "gb", []byte("b"), bServer)
	s.mu.Unlock()
	now := time.Unix(1_800_000_000, 0)
	if err := s.planner.Observe("site-a", aOwner, netip.MustParseAddrPort("198.51.100.1:40001"), now); err != nil {
		t.Fatal(err)
	}
	if err := s.planner.Observe("site-b", bOwner, netip.MustParseAddrPort("203.0.113.2:40002"), now); err != nil {
		t.Fatal(err)
	}
	plan, ok := s.planner.PlanFor("site-a", aOwner)
	if !ok || plan.Circuit != "c" || plan.Generation != "ga" || plan.PeerGeneration != "gb" {
		t.Fatalf("invalid relay plan: %#v", plan)
	}

	s.mu.Lock()
	newOwner := s.activateLegLocked("site-a", "ga2", []byte("new"), aServer)
	s.mu.Unlock()
	if newOwner == aOwner {
		t.Fatal("replacement owner did not advance")
	}
	if _, ok := s.planner.PlanFor("site-b", bOwner); ok {
		t.Fatal("peer retained plan after owner replacement")
	}
}
