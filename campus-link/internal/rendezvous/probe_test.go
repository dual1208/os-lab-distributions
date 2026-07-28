package rendezvous

import (
	"errors"
	"testing"
	"time"
)

func TestProbeRoundTripAndAuthentication(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	key := make([]byte, 32)
	key[0] = 7
	var session, nonce [16]byte
	session[0], nonce[0] = 1, 2
	want := Probe{Circuit: "campus", Session: session, Nonce: nonce, Site: 1,
		Role: RoleSender, Expires: now.Add(30 * time.Second), Attempt: 4}
	packet, err := want.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(packet, key, Expect{Circuit: "campus", Session: session, Site: 1, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != want.Role || got.Attempt != want.Attempt || got.Nonce != want.Nonce {
		t.Fatalf("round trip mismatch: %#v", got)
	}

	tampered := append([]byte(nil), packet...)
	tampered[20] ^= 1
	if _, err := Parse(tampered, key, Expect{Circuit: "campus", Session: session, Site: 1, Now: now}); !errors.Is(err, ErrProbeAuth) {
		t.Fatalf("tampered packet returned %v", err)
	}
	wrongKey := make([]byte, 32)
	if _, err := Parse(packet, wrongKey, Expect{Circuit: "campus", Session: session, Site: 1, Now: now}); !errors.Is(err, ErrProbeAuth) {
		t.Fatalf("wrong key returned %v", err)
	}
}

func TestProbeRejectsScopeAndLifetimeViolations(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	key := make([]byte, 32)
	var session, other, nonce [16]byte
	session[0], other[0], nonce[0] = 1, 2, 3
	probe := Probe{Circuit: "campus", Session: session, Nonce: nonce, Site: 2,
		Role: RoleReceiver, Expires: now.Add(20 * time.Second)}
	packet, err := probe.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		expect Expect
		err    error
	}{
		{"wrong circuit", Expect{Circuit: "other", Session: session, Site: 2, Now: now}, ErrUnexpectedProbe},
		{"wrong session", Expect{Circuit: "campus", Session: other, Site: 2, Now: now}, ErrUnexpectedProbe},
		{"wrong site", Expect{Circuit: "campus", Session: session, Site: 1, Now: now}, ErrUnexpectedProbe},
		{"expired", Expect{Circuit: "campus", Session: session, Site: 2, Now: now.Add(21 * time.Second)}, ErrProbeExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(packet, key, tt.expect); !errors.Is(err, tt.err) {
				t.Fatalf("got %v, want %v", err, tt.err)
			}
		})
	}
}

func TestReplayCacheIsBoundedAndExpires(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cache := NewReplayCache(1)
	var first, second [16]byte
	first[0], second[0] = 1, 2
	if !cache.Accept(first, now.Add(time.Second), now) {
		t.Fatal("first nonce rejected")
	}
	if cache.Accept(first, now.Add(time.Second), now) {
		t.Fatal("replay accepted")
	}
	if cache.Accept(second, now.Add(time.Second), now) {
		t.Fatal("cache limit bypassed")
	}
	if !cache.Accept(second, now.Add(2*time.Second), now.Add(time.Second)) {
		t.Fatal("expired entry was not removed")
	}
}

func TestCandidateValidation(t *testing.T) {
	got, err := ValidateCandidates([]string{"203.0.113.8:443", "203.0.113.8:443"}, false)
	if err != nil || len(got) != 1 {
		t.Fatalf("valid candidate rejected: %v %#v", err, got)
	}
	bad := []string{
		"127.0.0.1:443", "0.0.0.0:443", "224.0.0.1:443", "10.0.0.1:443",
		"255.255.255.255:443", "100.100.100.200:80", "203.0.113.8:0",
	}
	for _, candidate := range bad {
		if _, err := ValidateCandidates([]string{candidate}, false); !errors.Is(err, ErrInvalidCandidate) {
			t.Fatalf("unsafe candidate %q accepted", candidate)
		}
	}
	if _, err := ValidateCandidates([]string{"10.0.0.1:443"}, true); err != nil {
		t.Fatalf("explicit private candidate rejected: %v", err)
	}
}

func FuzzProbeParser(f *testing.F) {
	now := time.Unix(1_800_000_000, 0)
	key := make([]byte, 32)
	key[0] = 7
	var session, nonce [16]byte
	session[0], nonce[0] = 1, 2
	seed, err := (Probe{
		Circuit: "campus", Session: session, Nonce: nonce, Site: 1,
		Role: RoleSender, Expires: now.Add(30 * time.Second), Attempt: 1,
	}).Marshal(key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("CLPUNCH2"))
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _ = Parse(packet, key, Expect{Circuit: "campus", Session: session, Site: 1, Now: now})
	})
}
