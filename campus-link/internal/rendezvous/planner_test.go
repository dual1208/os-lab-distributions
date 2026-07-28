package rendezvous

import (
	"bytes"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestPlannerPairsCurrentOwners(t *testing.T) {
	p := NewPlanner(bytes.NewReader(bytes.Repeat([]byte{7}, 96)), "campus")
	now := time.Unix(1_800_000_000, 0)
	if err := p.Register("site-a", "ga", 1); err != nil {
		t.Fatal(err)
	}
	if err := p.Register("site-b", "gb", 2); err != nil {
		t.Fatal(err)
	}
	if err := p.Observe("site-a", 1, netip.MustParseAddrPort("198.51.100.1:40001"), now); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.PlanFor("site-a", 1); ok {
		t.Fatal("plan created before both observations")
	}
	if err := p.Observe("site-b", 2, netip.MustParseAddrPort("203.0.113.2:40002"), now); err != nil {
		t.Fatal(err)
	}
	a, ok := p.PlanFor("site-a", 1)
	if !ok {
		t.Fatal("site-a plan missing")
	}
	b, ok := p.PlanFor("site-b", 2)
	if !ok {
		t.Fatal("site-b plan missing")
	}
	if a.Session != b.Session || a.ProbeKey != b.ProbeKey || a.PathEpoch != b.PathEpoch {
		t.Fatal("peers received different session scope")
	}
	if a.Circuit != "campus" || b.Circuit != "campus" {
		t.Fatal("plan lost circuit scope")
	}
	if a.Role != "sender" || b.Role != "receiver" || a.Candidates[0] != "203.0.113.2:40002" || b.Candidates[0] != "198.51.100.1:40001" {
		t.Fatalf("invalid complementary plans: %#v %#v", a, b)
	}
	if a.ExpiresUnix-a.StartUnix != int64(planLifetime/time.Second)-1 {
		t.Fatal("plan lifetime changed")
	}
}

func TestPlannerRejectsStaleOwnerAndInvalidatesReplacement(t *testing.T) {
	random := append(bytes.Repeat([]byte{8}, 48), bytes.Repeat([]byte{9}, 48)...)
	p := NewPlanner(bytes.NewReader(random), "campus")
	now := time.Unix(1_800_000_000, 0)
	p.Register("site-a", "ga1", 10)
	p.Register("site-b", "gb", 20)
	p.Observe("site-a", 10, netip.MustParseAddrPort("198.51.100.1:40001"), now)
	p.Observe("site-b", 20, netip.MustParseAddrPort("203.0.113.2:40002"), now)
	old, _ := p.PlanFor("site-a", 10)

	if err := p.Register("site-a", "stale", 9); !errors.Is(err, ErrStaleOwner) {
		t.Fatalf("stale owner returned %v", err)
	}
	if err := p.Register("site-a", "ga2", 11); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.PlanFor("site-b", 20); ok {
		t.Fatal("peer retained plan for replaced generation")
	}
	if err := p.Observe("site-a", 10, netip.MustParseAddrPort("198.51.100.1:40003"), now); !errors.Is(err, ErrStaleOwner) {
		t.Fatalf("stale observation returned %v", err)
	}
	p.Observe("site-a", 11, netip.MustParseAddrPort("198.51.100.1:40003"), now)
	updated, ok := p.PlanFor("site-a", 11)
	if !ok || updated.PathEpoch <= old.PathEpoch || updated.Session == old.Session {
		t.Fatalf("replacement did not rotate plan: %#v", updated)
	}
}

func TestPlannerRebindingRotatesEpoch(t *testing.T) {
	p := NewPlanner(bytes.NewReader(bytes.Repeat([]byte{4}, 192)), "campus")
	now := time.Unix(1_800_000_000, 0)
	p.Register("site-a", "ga", 1)
	p.Register("site-b", "gb", 2)
	p.Observe("site-a", 1, netip.MustParseAddrPort("198.51.100.1:40001"), now)
	p.Observe("site-b", 2, netip.MustParseAddrPort("203.0.113.2:40002"), now)
	first, _ := p.PlanFor("site-a", 1)
	p.Observe("site-b", 2, netip.MustParseAddrPort("203.0.113.2:41002"), now.Add(time.Second))
	second, _ := p.PlanFor("site-a", 1)
	if second.PathEpoch != first.PathEpoch+1 || second.Candidates[0] == first.Candidates[0] {
		t.Fatalf("rebinding did not rotate epoch and candidate: %#v %#v", first, second)
	}
}

func TestPlannerConcurrentReadsAreSafe(t *testing.T) {
	p := NewPlanner(bytes.NewReader(bytes.Repeat([]byte{3}, 96)), "campus")
	now := time.Unix(1_800_000_000, 0)
	p.Register("site-a", "ga", 1)
	p.Register("site-b", "gb", 2)
	p.Observe("site-a", 1, netip.MustParseAddrPort("198.51.100.1:40001"), now)
	p.Observe("site-b", 2, netip.MustParseAddrPort("203.0.113.2:40002"), now)
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := p.PlanFor("site-a", 1); !ok {
				t.Error("concurrent plan read failed")
			}
		}()
	}
	wg.Wait()
}
