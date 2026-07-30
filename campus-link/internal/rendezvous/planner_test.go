package rendezvous

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

const (
	testVersion         = "test-v1"
	testDeploymentID    = "0123456789abcdef0123456789abcdef"
	testRelayGeneration = "abcdef0123456789abcdef0123456789"
)

type testEpochStore struct {
	mu        sync.Mutex
	namespace EpochNamespace
	seed      [32]byte
	next      uint64
	fail      bool
	replay    bool
}

func (s *testEpochStore) Namespace() EpochNamespace { return s.namespace }

func (s *testEpochStore) ReserveEpoch() (EpochReservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return EpochReservation{}, errors.New("injected persistence failure")
	}
	epoch := s.next
	if !s.replay {
		s.next++
	}
	return EpochReservation{Epoch: epoch, MaterialSeed: s.seed}, nil
}

func newTestPlanner(t *testing.T, seedByte byte) (*Planner, *testEpochStore) {
	t.Helper()
	store := &testEpochStore{
		namespace: EpochNamespace{DeploymentID: testDeploymentID, RelayGeneration: testRelayGeneration},
		next:      1,
	}
	for i := range store.seed {
		store.seed[i] = seedByte
	}
	planner, err := NewPlanner("campus", testVersion, store)
	if err != nil {
		t.Fatal(err)
	}
	return planner, store
}

func TestPlannerPairsCurrentOwners(t *testing.T) {
	p, _ := newTestPlanner(t, 7)
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
	if a.Circuit != "campus" || b.Circuit != "campus" || a.Version != testVersion || b.Version != testVersion ||
		a.DeploymentID != testDeploymentID || b.DeploymentID != testDeploymentID ||
		a.RelayGeneration != testRelayGeneration || b.RelayGeneration != testRelayGeneration {
		t.Fatal("plan lost authenticated namespace scope")
	}
	if a.Role != "sender" || b.Role != "receiver" || a.Candidates[0] != "203.0.113.2:40002" || b.Candidates[0] != "198.51.100.1:40001" {
		t.Fatalf("invalid complementary plans: %#v %#v", a, b)
	}
	if a.ExpiresUnix-a.StartUnix != int64(planLifetime/time.Second)-1 {
		t.Fatal("plan lifetime changed")
	}
}

func TestPlannerRejectsStaleOwnerAndInvalidatesReplacement(t *testing.T) {
	p, _ := newTestPlanner(t, 8)
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
	p, _ := newTestPlanner(t, 4)
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

func TestPlannerRotatesExpiredSessionWithoutNewObservation(t *testing.T) {
	p, _ := newTestPlanner(t, 6)
	now := time.Unix(1_800_000_000, 0)
	p.Register("site-a", "ga", 1)
	p.Register("site-b", "gb", 2)
	p.Observe("site-a", 1, netip.MustParseAddrPort("198.51.100.1:40001"), now)
	p.Observe("site-b", 2, netip.MustParseAddrPort("203.0.113.2:40002"), now)
	first, ok := p.PlanForAt("site-a", 1, now)
	if !ok {
		t.Fatal("initial plan missing")
	}
	second, ok := p.PlanForAt("site-a", 1, time.Unix(first.ExpiresUnix, 0))
	if !ok {
		t.Fatal("expired pair was not regenerated")
	}
	peer, ok := p.PlanForAt("site-b", 2, time.Unix(first.ExpiresUnix, 0))
	if !ok {
		t.Fatal("peer plan missing after rotation")
	}
	if second.PathEpoch != first.PathEpoch+1 || second.Session == first.Session ||
		second.Session != peer.Session || second.ProbeKey != peer.ProbeKey {
		t.Fatalf("expired plan did not rotate as one pair: first=%#v second=%#v peer=%#v", first, second, peer)
	}
}

func TestPlannerCandidateFailureCannotLeaveStalePlan(t *testing.T) {
	p, store := newTestPlanner(t, 4)
	now := time.Unix(1_800_000_000, 0)
	p.Register("site-a", "ga", 1)
	p.Register("site-b", "gb", 2)
	p.Observe("site-a", 1, netip.MustParseAddrPort("198.51.100.1:40001"), now)
	if err := p.Observe("site-b", 2, netip.MustParseAddrPort("203.0.113.2:40002"), now); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.PlanFor("site-a", 1); !ok {
		t.Fatal("initial plan missing")
	}
	store.mu.Lock()
	store.fail = true
	store.mu.Unlock()
	if err := p.Observe("site-b", 2, netip.MustParseAddrPort("203.0.113.2:41002"), now.Add(time.Second)); err == nil {
		t.Fatal("exhausted randomness unexpectedly produced a plan")
	}
	if _, ok := p.PlanFor("site-a", 1); ok {
		t.Fatal("random-generation failure retained stale site-a plan")
	}
	if _, ok := p.PlanFor("site-b", 2); ok {
		t.Fatal("random-generation failure retained stale site-b plan")
	}
}

func TestPlannerRejectsReplayedEpochFromInjectedStore(t *testing.T) {
	p, store := newTestPlanner(t, 10)
	now := time.Unix(1_800_000_000, 0)
	p.Register("site-a", "ga", 1)
	p.Register("site-b", "gb", 2)
	p.Observe("site-a", 1, netip.MustParseAddrPort("198.51.100.1:40001"), now)
	p.Observe("site-b", 2, netip.MustParseAddrPort("203.0.113.2:40002"), now)
	first, ok := p.PlanForAt("site-a", 1, now)
	if !ok {
		t.Fatal("initial plan missing")
	}
	store.mu.Lock()
	store.next = first.PathEpoch
	store.replay = true
	store.mu.Unlock()
	if _, ok := p.PlanForAt("site-a", 1, time.Unix(first.ExpiresUnix, 0)); ok {
		t.Fatal("replayed persistent epoch produced a second plan")
	}
}

func TestPlannerWithdrawKeepsOwnerButInvalidatesPair(t *testing.T) {
	p, _ := newTestPlanner(t, 5)
	now := time.Unix(1_800_000_000, 0)
	p.Register("site-a", "ga", 1)
	p.Register("site-b", "gb", 2)
	p.Observe("site-a", 1, netip.MustParseAddrPort("198.51.100.1:40001"), now)
	p.Observe("site-b", 2, netip.MustParseAddrPort("203.0.113.2:40002"), now)
	if !p.Withdraw("site-a", 1) {
		t.Fatal("current owner could not withdraw candidate")
	}
	if _, ok := p.PlanFor("site-b", 2); ok {
		t.Fatal("peer retained plan after candidate withdrawal")
	}
	if err := p.Observe("site-a", 1, netip.MustParseAddrPort("198.51.100.1:41001"), now.Add(time.Second)); err != nil {
		t.Fatal("withdraw incorrectly removed control ownership")
	}
	if _, ok := p.PlanFor("site-a", 1); !ok {
		t.Fatal("owner did not regenerate plans after a fresh observation")
	}
}

func TestPlannerConcurrentReadsAreSafe(t *testing.T) {
	p, _ := newTestPlanner(t, 3)
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
