package rendezvous

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"
)

const (
	probeMagic       = "CLPUNCH2"
	ProbeSize        = 104
	MaxCandidates    = 16
	MaxSessionTTL    = 60 * time.Second
	defaultReplayMax = 1024
)

type Role byte

const (
	RoleSender   Role = 1
	RoleReceiver Role = 2
)

type Probe struct {
	Circuit  string
	Session  [16]byte
	Nonce    [16]byte
	Site     byte
	Role     Role
	Response bool
	Expires  time.Time
	Attempt  uint32
}

type Expect struct {
	Circuit string
	Session [16]byte
	Site    byte
	Now     time.Time
}

var (
	ErrInvalidProbe     = errors.New("invalid rendezvous probe")
	ErrProbeAuth        = errors.New("rendezvous probe authentication failed")
	ErrProbeExpired     = errors.New("rendezvous probe expired or outside lifetime bound")
	ErrUnexpectedProbe  = errors.New("unexpected rendezvous probe")
	ErrInvalidCandidate = errors.New("invalid rendezvous candidate")
)

func (p Probe) Marshal(key []byte) ([]byte, error) {
	if len(key) != 32 || p.Circuit == "" || p.Site == 0 || !validRole(p.Role) ||
		p.Expires.IsZero() || p.Session == ([16]byte{}) || p.Nonce == ([16]byte{}) {
		return nil, ErrInvalidProbe
	}
	b := make([]byte, ProbeSize)
	copy(b[:8], probeMagic)
	b[8] = 2
	b[9] = p.Site
	b[10] = byte(p.Role)
	if p.Response {
		b[11] = 1
	}
	binary.BigEndian.PutUint64(b[12:20], uint64(p.Expires.Unix()))
	binary.BigEndian.PutUint32(b[20:24], p.Attempt)
	copy(b[24:40], p.Session[:])
	copy(b[40:56], p.Nonce[:])
	circuitHash := sha256.Sum256([]byte(p.Circuit))
	copy(b[56:72], circuitHash[:16])
	copy(b[72:], sign(key, b[:72]))
	return b, nil
}

func Parse(packet, key []byte, expect Expect) (Probe, error) {
	var p Probe
	if len(packet) != ProbeSize || len(key) != 32 || string(packet[:8]) != probeMagic ||
		packet[8] != 2 || packet[9] == 0 || !validRole(Role(packet[10])) || packet[11] > 1 {
		return p, ErrInvalidProbe
	}
	if !hmac.Equal(packet[72:], sign(key, packet[:72])) {
		return p, ErrProbeAuth
	}
	p.Site = packet[9]
	p.Role = Role(packet[10])
	p.Response = packet[11] == 1
	p.Expires = time.Unix(int64(binary.BigEndian.Uint64(packet[12:20])), 0)
	p.Attempt = binary.BigEndian.Uint32(packet[20:24])
	copy(p.Session[:], packet[24:40])
	copy(p.Nonce[:], packet[40:56])
	p.Circuit = expect.Circuit

	now := expect.Now
	if now.IsZero() {
		now = time.Now()
	}
	if p.Expires.Before(now) || p.Expires.After(now.Add(MaxSessionTTL)) {
		return Probe{}, ErrProbeExpired
	}
	circuitHash := sha256.Sum256([]byte(expect.Circuit))
	if expect.Circuit == "" || !hmac.Equal(packet[56:72], circuitHash[:16]) ||
		p.Session != expect.Session || p.Site != expect.Site {
		return Probe{}, ErrUnexpectedProbe
	}
	return p, nil
}

func ValidateCandidates(values []string, allowPrivate bool) ([]netip.AddrPort, error) {
	if len(values) == 0 || len(values) > MaxCandidates {
		return nil, ErrInvalidCandidate
	}
	out := make([]netip.AddrPort, 0, len(values))
	seen := make(map[netip.AddrPort]struct{}, len(values))
	for _, value := range values {
		candidate, err := netip.ParseAddrPort(value)
		if err != nil || !candidate.Addr().Is4() || candidate.Port() == 0 {
			return nil, ErrInvalidCandidate
		}
		addr := candidate.Addr().Unmap()
		if addr.IsUnspecified() || addr.IsMulticast() || addr.IsLoopback() ||
			addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
			addr == netip.MustParseAddr("255.255.255.255") ||
			addr == netip.MustParseAddr("100.100.100.200") ||
			(addr.IsPrivate() && !allowPrivate) {
			return nil, ErrInvalidCandidate
		}
		candidate = netip.AddrPortFrom(addr, candidate.Port())
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	if len(out) == 0 {
		return nil, ErrInvalidCandidate
	}
	return out, nil
}

type ReplayCache struct {
	mu      sync.Mutex
	entries map[[16]byte]time.Time
	max     int
}

func NewReplayCache(max int) *ReplayCache {
	if max <= 0 {
		max = defaultReplayMax
	}
	return &ReplayCache{entries: make(map[[16]byte]time.Time), max: max}
}

// Accept returns false for a duplicate nonce or when the bounded cache cannot
// safely remember another unexpired nonce.
func (r *ReplayCache) Accept(nonce [16]byte, expires, now time.Time) bool {
	if nonce == ([16]byte{}) || !expires.After(now) || expires.After(now.Add(MaxSessionTTL)) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for existing, expiry := range r.entries {
		if !expiry.After(now) {
			delete(r.entries, existing)
		}
	}
	if _, exists := r.entries[nonce]; exists || len(r.entries) >= r.max {
		return false
	}
	r.entries[nonce] = expires
	return true
}

func validRole(role Role) bool { return role == RoleSender || role == RoleReceiver }

func sign(key, body []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(body)
	return mac.Sum(nil)
}
