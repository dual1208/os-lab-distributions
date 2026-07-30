package rendezvous

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
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
	mu              sync.Mutex
	circuit         string
	version         string
	deploymentID    string
	relayGeneration string
	epochStore      EpochStore
	legs            map[string]planLeg
	plans           map[string]control.RendezvousPlan
	lastEpoch       uint64
	pairKey         string
}

func NewPlanner(circuit, version string, epochStore EpochStore) (*Planner, error) {
	if circuit == "" || !control.ValidSourceVersion(version) || epochStore == nil {
		return nil, ErrEpochState
	}
	namespace := epochStore.Namespace()
	if !control.ValidDeploymentID(namespace.DeploymentID) || !control.ValidRelayGeneration(namespace.RelayGeneration) {
		return nil, ErrEpochState
	}
	return &Planner{
		circuit: circuit, version: version, deploymentID: namespace.DeploymentID,
		relayGeneration: namespace.RelayGeneration, epochStore: epochStore,
		legs: map[string]planLeg{"site-a": {}, "site-b": {}}, plans: make(map[string]control.RendezvousPlan),
	}, nil
}

func (p *Planner) Namespace() EpochNamespace {
	return EpochNamespace{DeploymentID: p.deploymentID, RelayGeneration: p.relayGeneration}
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
	// A candidate change invalidates the old pair before randomness or plan
	// construction can fail. PlanFor must never advertise a stale endpoint.
	p.invalidatePlansLocked()
	return p.maybePlanLocked(now)
}

// Withdraw removes one current owner's observed candidate without replacing
// its authenticated control ownership. It is used when a newly proven relay
// tuple is not eligible for direct-path advertisement.
func (p *Planner) Withdraw(site string, owner uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !validSite(site) || p.legs[site].owner != owner {
		return false
	}
	leg := p.legs[site]
	leg.candidate = netip.AddrPort{}
	p.legs[site] = leg
	p.invalidatePlansLocked()
	return true
}

func (p *Planner) PlanFor(site string, owner uint64) (control.RendezvousPlan, bool) {
	return p.PlanForAt(site, owner, time.Now())
}

// PlanForAt returns only a current plan. Once a pair expires it is erased and,
// while both authenticated owners still have candidates, replaced with fresh
// session/key material and a higher path epoch.
func (p *Planner) PlanForAt(site string, owner uint64, now time.Time) (control.RendezvousPlan, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !validSite(site) || p.legs[site].owner != owner || now.IsZero() {
		return control.RendezvousPlan{}, false
	}
	plan, ok := p.plans[site]
	if ok && now.Unix() >= plan.ExpiresUnix {
		p.invalidatePlansLocked()
		plan = control.RendezvousPlan{}
		ok = false
	}
	if !ok {
		if err := p.maybePlanLocked(now); err != nil {
			return control.RendezvousPlan{}, false
		}
		plan, ok = p.plans[site]
		if !ok {
			return control.RendezvousPlan{}, false
		}
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
	reservation, err := p.epochStore.ReserveEpoch()
	if err != nil {
		return err
	}
	if reservation.Epoch == 0 || reservation.Epoch <= p.lastEpoch || reservation.MaterialSeed == ([32]byte{}) {
		return ErrEpochState
	}
	session, key := derivePlanMaterial(reservation, p.circuit, p.version, p.deploymentID, p.relayGeneration)
	if session == ([16]byte{}) || key == ([32]byte{}) {
		return ErrNamespaceEntropy
	}
	start := now.Add(time.Second).Unix()
	expires := now.Add(planLifetime).Unix()
	sessionHex, keyHex := hex.EncodeToString(session[:]), hex.EncodeToString(key[:])
	p.plans = map[string]control.RendezvousPlan{
		"site-a": {
			Type: "rendezvous-plan", Circuit: p.circuit, Version: p.version,
			DeploymentID: p.deploymentID, RelayGeneration: p.relayGeneration,
			Generation: a.generation, PeerGeneration: b.generation,
			Session: sessionHex, ProbeKey: keyHex, Role: "sender", Attempt: 1,
			PathEpoch: reservation.Epoch, StartUnix: start, ExpiresUnix: expires,
			Candidates: []string{b.candidate.String()},
		},
		"site-b": {
			Type: "rendezvous-plan", Circuit: p.circuit, Version: p.version,
			DeploymentID: p.deploymentID, RelayGeneration: p.relayGeneration,
			Generation: b.generation, PeerGeneration: a.generation,
			Session: sessionHex, ProbeKey: keyHex, Role: "receiver", Attempt: 1,
			PathEpoch: reservation.Epoch, StartUnix: start, ExpiresUnix: expires,
			Candidates: []string{a.candidate.String()},
		},
	}
	p.lastEpoch = reservation.Epoch
	p.pairKey = pairKey
	return nil
}

func derivePlanMaterial(reservation EpochReservation, circuit, version, deploymentID, relayGeneration string) ([16]byte, [32]byte) {
	context := make([]byte, 8)
	binary.BigEndian.PutUint64(context, reservation.Epoch)
	for _, value := range []string{circuit, version, deploymentID, relayGeneration} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		context = append(context, length[:]...)
		context = append(context, value...)
	}

	sessionMAC := hmac.New(sha256.New, reservation.MaterialSeed[:])
	_, _ = sessionMAC.Write([]byte("campus-link/rendezvous/session/v2\x00"))
	_, _ = sessionMAC.Write(context)
	sessionDigest := sessionMAC.Sum(nil)
	var session [16]byte
	copy(session[:], sessionDigest[:len(session)])

	keyMAC := hmac.New(sha256.New, reservation.MaterialSeed[:])
	_, _ = keyMAC.Write([]byte("campus-link/rendezvous/probe-key/v2\x00"))
	_, _ = keyMAC.Write(context)
	var key [32]byte
	copy(key[:], keyMAC.Sum(nil))
	return session, key
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
