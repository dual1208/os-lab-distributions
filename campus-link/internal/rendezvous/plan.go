package rendezvous

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
)

const planClockSkew = 5 * time.Second

var ErrInvalidPlan = errors.New("invalid rendezvous plan")

type Plan struct {
	Circuit         string
	Version         string
	DeploymentID    string
	RelayGeneration string
	Generation      string
	PeerGeneration  string
	Session         [16]byte
	ProbeKey        [32]byte
	Role            Role
	Attempt         uint32
	PathEpoch       uint64
	Start           time.Time
	Expires         time.Time
	Candidates      []netip.AddrPort
}

type PlanExpect struct {
	Circuit         string
	Version         string
	DeploymentID    string
	RelayGeneration string
	Generation      string
	MinPathEpoch    uint64
	AllowMinEpoch   bool
	Now             time.Time
	AllowPrivate    bool
}

func ValidatePlan(message control.RendezvousPlan, expect PlanExpect) (Plan, error) {
	var plan Plan
	if message.Type != "rendezvous-plan" || message.Circuit == "" || message.Circuit != expect.Circuit ||
		!control.ValidSourceVersion(expect.Version) || message.Version != expect.Version ||
		!control.ValidDeploymentID(expect.DeploymentID) || message.DeploymentID != expect.DeploymentID ||
		!control.ValidRelayGeneration(expect.RelayGeneration) || message.RelayGeneration != expect.RelayGeneration ||
		message.Generation == "" || message.Generation != expect.Generation || message.PeerGeneration == "" ||
		message.PeerGeneration == message.Generation || message.PathEpoch == 0 || message.PathEpoch < expect.MinPathEpoch ||
		(message.PathEpoch == expect.MinPathEpoch && !expect.AllowMinEpoch) ||
		(expect.MinPathEpoch != 0 && message.PathEpoch-expect.MinPathEpoch > 1024) ||
		message.Attempt == 0 || message.Attempt > 64 {
		return plan, ErrInvalidPlan
	}
	switch message.Role {
	case "sender":
		plan.Role = RoleSender
	case "receiver":
		plan.Role = RoleReceiver
	default:
		return Plan{}, ErrInvalidPlan
	}
	session, err := hex.DecodeString(message.Session)
	if err != nil || len(session) != len(plan.Session) {
		return Plan{}, ErrInvalidPlan
	}
	key, err := hex.DecodeString(message.ProbeKey)
	if err != nil || len(key) != len(plan.ProbeKey) {
		return Plan{}, ErrInvalidPlan
	}
	copy(plan.Session[:], session)
	copy(plan.ProbeKey[:], key)
	if plan.Session == ([16]byte{}) || plan.ProbeKey == ([32]byte{}) {
		return Plan{}, ErrInvalidPlan
	}
	start := time.Unix(message.StartUnix, 0)
	expires := time.Unix(message.ExpiresUnix, 0)
	now := expect.Now
	if now.IsZero() {
		now = time.Now()
	}
	if !expires.After(start) || expires.Sub(start) > MaxSessionTTL ||
		start.After(now.Add(MaxSessionTTL)) || now.After(expires.Add(planClockSkew)) {
		return Plan{}, ErrInvalidPlan
	}
	candidates, err := ValidateCandidates(message.Candidates, expect.AllowPrivate)
	if err != nil {
		return Plan{}, ErrInvalidPlan
	}
	plan.Circuit = message.Circuit
	plan.Version = message.Version
	plan.DeploymentID = message.DeploymentID
	plan.RelayGeneration = message.RelayGeneration
	plan.Generation = message.Generation
	plan.PeerGeneration = message.PeerGeneration
	plan.Attempt = message.Attempt
	plan.PathEpoch = message.PathEpoch
	plan.Start = start
	plan.Expires = expires
	plan.Candidates = candidates
	return plan, nil
}
