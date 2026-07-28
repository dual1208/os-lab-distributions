package relay

import (
	"testing"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
)

func TestLatestControlSessionExclusivelyOwnsLeg(t *testing.T) {
	s, err := New(config.Relay{Circuit: "c", Prefixes: map[string]string{"site-a": "10.81.0.0/24", "site-b": "10.82.0.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	oldOwner := s.activateLegLocked("site-a", "same-generation", []byte("old"))
	newOwner := s.activateLegLocked("site-a", "same-generation", []byte("new"))
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

func TestOuterDatagramLimitIsBounded(t *testing.T) {
	if maxOuterDatagramSize < 1280 || maxOuterDatagramSize > 4096 {
		t.Fatalf("unexpected outer datagram limit: %d", maxOuterDatagramSize)
	}
}
