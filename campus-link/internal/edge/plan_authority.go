package edge

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/datapath"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/rendezvous"
)

const planAuthorityNamespaceDomain = "campus-link/edge/plan-authority/v1"

var (
	errInvalidPlanAuthorityNamespace = errors.New("invalid plan authority namespace")
	errInvalidRelayTelemetry         = errors.New("invalid relay telemetry")
)

type planSessionLease struct {
	namespace string
	serial    uint64
	authority context.Context
}

type authorizedPlan struct {
	rendezvous.Plan
	lease planSessionLease
	// leaseRebind is admission proof for one fully validated, byte-exact
	// same-namespace plan delivered under a fresh control lease. It transfers
	// only future retry authority; the established data connection is not
	// owned by the replacement control lease.
	leaseRebind bool
}

// rememberedPlan retains the exact control value as well as its validated
// form. Comparing only the normalized Plan would incorrectly treat a
// wire-different candidate list as an exact duplicate.
type rememberedPlan struct {
	message    control.RendezvousPlan
	authorized authorizedPlan
}

// planAuthorityNamespace is a local identity key, not a wire encoding. Every
// component, including the domain, is length-prefixed so field boundaries are
// canonical and cannot be shifted with delimiter bytes.
func planAuthorityNamespace(version, deploymentID, relayGeneration string) (string, error) {
	if !control.ValidSourceVersion(version) || !control.ValidDeploymentID(deploymentID) ||
		!control.ValidRelayGeneration(relayGeneration) {
		return "", errInvalidPlanAuthorityNamespace
	}
	values := []string{planAuthorityNamespaceDomain, version, deploymentID, relayGeneration}
	encoded := make([]byte, 0, len(planAuthorityNamespaceDomain)+len(version)+len(deploymentID)+len(relayGeneration)+4*len(values))
	for _, value := range values {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		encoded = append(encoded, length[:]...)
		encoded = append(encoded, value...)
	}
	return string(encoded), nil
}

func (lease planSessionLease) valid() bool {
	return lease.namespace != "" && lease.serial != 0 && lease.authority != nil && lease.authority.Done() != nil
}

func samePlanSession(a, b planSessionLease) bool {
	return a.valid() && b.valid() && a.namespace == b.namespace && a.serial == b.serial &&
		a.authority.Done() == b.authority.Done()
}

func cloneRendezvousPlanMessage(message control.RendezvousPlan) control.RendezvousPlan {
	message.Candidates = append([]string(nil), message.Candidates...)
	return message
}

func sameRendezvousPlanMessage(a, b control.RendezvousPlan) bool {
	return reflect.DeepEqual(a, b)
}

func sameValidatedPlan(a, b rendezvous.Plan) bool {
	return reflect.DeepEqual(a, b)
}

func (r *Runner) planAuthorityCurrent(lease planSessionLease, epoch uint64) bool {
	if r == nil || epoch == 0 || !lease.valid() {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.planAuthorityCurrentLocked(lease, epoch)
}

func (r *Runner) planAuthorityCurrentLocked(lease planSessionLease, epoch uint64) bool {
	return epoch != 0 && r.planSessionCurrentLocked(lease) && r.planEpoch.Load() == epoch
}

func (r *Runner) planSessionCurrentLocked(lease planSessionLease) bool {
	if !lease.valid() || r.planSessionAuthority == nil || r.planSessionAuthority.Done() == nil ||
		r.planNamespace != lease.namespace || r.activePlanSession != lease.serial ||
		r.planSessionAuthority.Done() != lease.authority.Done() {
		return false
	}
	select {
	case <-lease.authority.Done():
		return false
	default:
		return true
	}
}

func (r *Runner) recordRelayTelemetry(lease planSessionLease, sequence uint64, telemetry *control.RelayTelemetry) error {
	if r == nil || sequence == 0 || telemetry == nil || !lease.valid() {
		return errInvalidRelayTelemetry
	}
	r.mu.Lock()
	if !r.planSessionCurrentLocked(lease) {
		r.mu.Unlock()
		return errInvalidRelayTelemetry
	}
	previous := r.state.RelayTelemetry
	if previous != nil && (previous.ControlSession != lease.serial || sequence <= previous.Sequence ||
		telemetry.ForwardedSiteA < previous.ForwardedPackets.SiteA ||
		telemetry.ForwardedSiteABytes < previous.ForwardedBytes.SiteA ||
		telemetry.ForwardedSiteB < previous.ForwardedPackets.SiteB ||
		telemetry.ForwardedSiteBBytes < previous.ForwardedBytes.SiteB ||
		telemetry.Dropped < previous.DroppedPackets ||
		telemetry.DroppedBytes < previous.DroppedBytes) {
		r.mu.Unlock()
		return errInvalidRelayTelemetry
	}
	r.state.RelayTelemetry = &relayTelemetryStatus{
		ControlSession: lease.serial,
		Sequence:       sequence,
		ForwardedPackets: relayForwardedPacketStatus{
			SiteA: telemetry.ForwardedSiteA,
			SiteB: telemetry.ForwardedSiteB,
		},
		ForwardedBytes: relayForwardedPacketStatus{
			SiteA: telemetry.ForwardedSiteABytes,
			SiteB: telemetry.ForwardedSiteBBytes,
		},
		DroppedPackets: telemetry.Dropped,
		DroppedBytes:   telemetry.DroppedBytes,
	}
	r.mu.Unlock()
	r.writeStatus()
	return nil
}

// withPlanAuthority makes an activation phase and control-session revocation
// one serialized operation. If a phase wins the lock it may finish before the
// revocation; once revocation wins, no later phase can mutate the mux.
func (r *Runner) withPlanAuthority(lease planSessionLease, epoch uint64, operation func() error) error {
	if r == nil || operation == nil {
		return datapath.ErrStalePath
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.planAuthorityCurrentLocked(lease, epoch) {
		return datapath.ErrStalePath
	}
	return operation()
}

func planAttemptContext(parent context.Context, lease planSessionLease, deadline time.Time) (context.Context, context.CancelFunc) {
	if !lease.valid() {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, cancel
	}
	// Authority is the parent so its cancellation propagates synchronously.
	// The data lifetime remains a secondary bound and cannot prolong authority.
	ctx, cancel := context.WithDeadline(lease.authority, deadline)
	stopParent := context.AfterFunc(parent, cancel)
	return ctx, func() {
		stopParent()
		cancel()
	}
}
