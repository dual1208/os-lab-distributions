package pathstate

import (
	"sync"
	"time"
)

type State string

const (
	Offline       State = "offline"
	RelayReady    State = "relay-ready"
	Punching      State = "punching"
	DirectProbing State = "direct-probing"
	Direct        State = "direct"
)

type Snapshot struct {
	State         State
	Attempt       State
	Generation    uint64
	ActiveEpoch   uint64
	AttemptEpoch  uint64
	RelayHealthy  bool
	DirectHealthy bool
	RouteUp       bool
}

type Manager struct {
	mu            sync.Mutex
	state         State
	attempt       State
	generation    uint64
	activeEpoch   uint64
	attemptEpoch  uint64
	relayHealthy  bool
	directHealthy bool
	probingSince  time.Time
}

func New(generation uint64) *Manager {
	return &Manager{state: Offline, generation: generation}
}

func (m *Manager) ReplaceGeneration(generation uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if generation <= m.generation {
		return
	}
	m.generation = generation
	m.activeEpoch = 0
	m.attemptEpoch = 0
	m.relayHealthy = false
	m.directHealthy = false
	m.probingSince = time.Time{}
	m.state = Offline
	m.attempt = Offline
}

func (m *Manager) SetRelayHealth(generation uint64, healthy bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if generation != m.generation {
		return false
	}
	m.relayHealthy = healthy
	if m.directHealthy {
		m.state = Direct
	} else if healthy {
		m.state = RelayReady
	} else if m.state != Punching && m.state != DirectProbing {
		m.state = Offline
	}
	return true
}

func (m *Manager) BeginPunch(generation, epoch uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if generation != m.generation || epoch <= m.activeEpoch || epoch <= m.attemptEpoch {
		return false
	}
	m.attemptEpoch = epoch
	m.probingSince = time.Time{}
	m.attempt = Punching
	return true
}

func (m *Manager) BeginDirectProbe(generation, epoch uint64, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if generation != m.generation || epoch != m.attemptEpoch || m.attempt != Punching {
		return false
	}
	m.probingSince = now
	m.attempt = DirectProbing
	return true
}

func (m *Manager) ActivateDirect(generation, epoch uint64, now time.Time, minStable time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if generation != m.generation || epoch != m.attemptEpoch || m.attempt != DirectProbing ||
		m.probingSince.IsZero() || now.Before(m.probingSince) || now.Sub(m.probingSince) < minStable {
		return false
	}
	m.activeEpoch = epoch
	m.attemptEpoch = 0
	m.directHealthy = true
	m.attempt = Offline
	m.state = Direct
	return true
}

func (m *Manager) DirectFailed(generation, epoch uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if generation != m.generation {
		return false
	}
	if epoch == m.attemptEpoch && m.attempt != Offline {
		m.attemptEpoch = 0
		m.attempt = Offline
		m.probingSince = time.Time{}
		return true
	}
	if epoch != m.activeEpoch || !m.directHealthy {
		return false
	}
	m.directHealthy = false
	m.probingSince = time.Time{}
	if m.relayHealthy {
		m.state = RelayReady
	} else {
		m.state = Offline
	}
	return true
}

func (m *Manager) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{
		State: m.state, Attempt: m.attempt, Generation: m.generation,
		ActiveEpoch: m.activeEpoch, AttemptEpoch: m.attemptEpoch,
		RelayHealthy: m.relayHealthy, DirectHealthy: m.directHealthy,
		RouteUp: m.relayHealthy || m.directHealthy,
	}
}
