package rendezvous

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
)

const planLifetime = 45 * time.Second

var ErrStaleOwner = errors.New("stale rendezvous owner")

type planLeg struct {
	owner      uint64
	generation string
	candidate  netip.AddrPort
}

type Planner struct {
	mu      sync.Mutex
	random  io.Reader
	circuit string
	legs    map[string]planLeg
	plans   map[string]control.RendezvousPlan
	epoch   uint64
	pairKey string
}

func NewPlanner(random io.Reader, circuit string) *Planner {
	if random == nil {
		random = rand.Reader
	}
	return &Planner{
		random:  random,
		circuit: circuit,
		legs:    map[string]planLeg{"site-a": {}, "site-b": {}},
		plans:   make(map[string]control.RendezvousPlan),
	}
}

// Register establishes the only control-session owner allowed to publish a
// candidate for one site. Owner numbers must increase on replacement.
func (p *Planner) Register(site, generation string, owner uint64) error {
	if !validSite(site) || generation == "" || owner == 0 {
		return ErrStaleOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	current := p.legs[site]
	if current.owner == owner && current.generation == generation {
		return nil
	}
	if owner <= current.owner {
		return ErrStaleOwner
	}
	p.legs[site] = planLeg{owner: owner, generation: generation}
	p.invalidatePlansLocked()
	return nil
}

// Observe records the reflexive address seen from the eventual data socket.
// A new pair of plans is created once both current owners have observations.
func (p *Planner) Observe(site string, owner uint64, candidate netip.AddrPort, now time.Time) error {
	if !validSite(site) || !validObservedCandidate(candidate) || now.IsZero() {
		return ErrInvalidCandidate
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	leg := p.legs[site]
	if leg.owner == 0 || leg.owner != owner {
		return ErrStaleOwner
	}
	leg.candidate = candidate
	p.legs[site] = leg
	return p.maybePlanLocked(now)
}

func (p *Planner) PlanFor(site string, owner uint64) (control.RendezvousPlan, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !validSite(site) || p.legs[site].owner != owner {
		return control.RendezvousPlan{}, false
	}
	plan, ok := p.plans[site]
	if !ok {
		return control.RendezvousPlan{}, false
	}
	plan.Candidates = append([]string(nil), plan.Candidates...)
	return plan, true
}

func (p *Planner) Invalidate(site string, owner uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !validSite(site) || p.legs[site].owner != owner {
		return false
	}
	p.legs[site] = planLeg{}
	p.invalidatePlansLocked()
	return true
}

func (p *Planner) maybePlanLocked(now time.Time) error {
	a, b := p.legs["site-a"], p.legs["site-b"]
	if a.owner == 0 || b.owner == 0 || !a.candidate.IsValid() || !b.candidate.IsValid() {
		return nil
	}
	pairKey := a.generation + "\x00" + b.generation + "\x00" + a.candidate.String() + "\x00" + b.candidate.String()
	if pairKey == p.pairKey && len(p.plans) == 2 {
		return nil
	}
	session := make([]byte, 16)
	key := make([]byte, 32)
	if _, err := io.ReadFull(p.random, session); err != nil {
		return err
	}
	if _, err := io.ReadFull(p.random, key); err != nil {
		return err
	}
	p.epoch++
	start := now.Add(time.Second).Unix()
	expires := now.Add(planLifetime).Unix()
	sessionHex, keyHex := hex.EncodeToString(session), hex.EncodeToString(key)
	p.plans = map[string]control.RendezvousPlan{
		"site-a": {
			Type: "rendezvous-plan", Circuit: p.circuit, Generation: a.generation, PeerGeneration: b.generation,
			Session: sessionHex, ProbeKey: keyHex, Role: "receiver", Attempt: 1,
			PathEpoch: p.epoch, StartUnix: start, ExpiresUnix: expires,
			Candidates: []string{b.candidate.String()},
		},
		"site-b": {
			Type: "rendezvous-plan", Circuit: p.circuit, Generation: b.generation, PeerGeneration: a.generation,
			Session: sessionHex, ProbeKey: keyHex, Role: "sender", Attempt: 1,
			PathEpoch: p.epoch, StartUnix: start, ExpiresUnix: expires,
			Candidates: []string{a.candidate.String()},
		},
	}
	p.pairKey = pairKey
	return nil
}

func (p *Planner) invalidatePlansLocked() {
	p.plans = make(map[string]control.RendezvousPlan)
	p.pairKey = ""
}

func validObservedCandidate(candidate netip.AddrPort) bool {
	if !candidate.IsValid() || !candidate.Addr().Is4() || candidate.Port() == 0 {
		return false
	}
	addr := candidate.Addr().Unmap()
	return !addr.IsUnspecified() && !addr.IsMulticast() && !addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() && addr != netip.MustParseAddr("255.255.255.255") &&
		addr != netip.MustParseAddr("100.100.100.200")
}

func validSite(site string) bool { return site == "site-a" || site == "site-b" }
