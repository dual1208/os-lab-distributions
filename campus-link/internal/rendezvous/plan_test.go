package rendezvous

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
)

func validPlanMessage(now time.Time) control.RendezvousPlan {
	return control.RendezvousPlan{
		Type: "rendezvous-plan", Circuit: "campus", Generation: "ga", PeerGeneration: "gb",
		Session:  hex.EncodeToString([]byte("0123456789abcdef")),
		ProbeKey: hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		Role:     "sender", Attempt: 1, PathEpoch: 3,
		StartUnix: now.Add(time.Second).Unix(), ExpiresUnix: now.Add(45 * time.Second).Unix(),
		Candidates: []string{"203.0.113.2:40002"},
	}
}

func TestValidatePlan(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	message := validPlanMessage(now)
	plan, err := ValidatePlan(message, PlanExpect{Circuit: "campus", Generation: "ga", MinPathEpoch: 2, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Role != RoleSender || plan.PathEpoch != 3 || len(plan.Candidates) != 1 || plan.Candidates[0].String() != message.Candidates[0] {
		t.Fatalf("plan mismatch: %#v", plan)
	}
}

func TestValidatePlanRejectsUntrustedFields(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tests := []struct {
		name   string
		mutate func(*control.RendezvousPlan)
	}{
		{"wrong type", func(p *control.RendezvousPlan) { p.Type = "other" }},
		{"wrong circuit", func(p *control.RendezvousPlan) { p.Circuit = "other" }},
		{"wrong generation", func(p *control.RendezvousPlan) { p.Generation = "old" }},
		{"same peer generation", func(p *control.RendezvousPlan) { p.PeerGeneration = p.Generation }},
		{"stale epoch", func(p *control.RendezvousPlan) { p.PathEpoch = 2 }},
		{"zero attempt", func(p *control.RendezvousPlan) { p.Attempt = 0 }},
		{"excess attempts", func(p *control.RendezvousPlan) { p.Attempt = 65 }},
		{"wrong role", func(p *control.RendezvousPlan) { p.Role = "both" }},
		{"short session", func(p *control.RendezvousPlan) { p.Session = "00" }},
		{"zero session", func(p *control.RendezvousPlan) { p.Session = string(make([]byte, 32)) }},
		{"short key", func(p *control.RendezvousPlan) { p.ProbeKey = "00" }},
		{"expired", func(p *control.RendezvousPlan) { p.ExpiresUnix = now.Add(-6 * time.Second).Unix() }},
		{"long lifetime", func(p *control.RendezvousPlan) { p.ExpiresUnix = now.Add(70 * time.Second).Unix() }},
		{"far future", func(p *control.RendezvousPlan) {
			p.StartUnix = now.Add(61 * time.Second).Unix()
			p.ExpiresUnix = now.Add(62 * time.Second).Unix()
		}},
		{"private candidate", func(p *control.RendezvousPlan) { p.Candidates = []string{"10.0.0.1:443"} }},
		{"metadata candidate", func(p *control.RendezvousPlan) { p.Candidates = []string{"100.100.100.200:80"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := validPlanMessage(now)
			tt.mutate(&message)
			_, err := ValidatePlan(message, PlanExpect{Circuit: "campus", Generation: "ga", MinPathEpoch: 2, Now: now})
			if !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("unsafe plan returned %v", err)
			}
		})
	}
}

func TestValidatePlanAllowsExplicitPrivateCandidate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	message := validPlanMessage(now)
	message.Candidates = []string{"10.0.0.1:443"}
	if _, err := ValidatePlan(message, PlanExpect{Circuit: "campus", Generation: "ga", MinPathEpoch: 2, Now: now, AllowPrivate: true}); err != nil {
		t.Fatalf("explicit private policy rejected: %v", err)
	}
}
