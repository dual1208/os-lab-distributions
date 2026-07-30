package edge

import (
	"context"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/datapath"
)

func TestSameEpochPlanNeverBypassesValidationOrExactConflictCheck(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	runner, lease, message, _ := acceptedSameEpochFixture(t, now)

	tests := []struct {
		name   string
		mutate func(*control.RendezvousPlan)
	}{
		{name: "malformed session", mutate: func(plan *control.RendezvousPlan) { plan.Session = "00" }},
		{name: "conflicting session", mutate: func(plan *control.RendezvousPlan) {
			plan.Session = "11111111111111111111111111111111"
		}},
		{name: "conflicting probe key", mutate: func(plan *control.RendezvousPlan) {
			plan.ProbeKey = "1111111111111111111111111111111111111111111111111111111111111111"
		}},
		{name: "conflicting candidate", mutate: func(plan *control.RendezvousPlan) {
			plan.Candidates = []string{"198.51.100.55:42000"}
		}},
		{name: "wire-different duplicate candidate", mutate: func(plan *control.RendezvousPlan) {
			plan.Candidates = append(plan.Candidates, plan.Candidates[0])
		}},
		{name: "foreign namespace", mutate: func(plan *control.RendezvousPlan) {
			plan.RelayGeneration = "11111111111111111111111111111111"
		}},
		{name: "wrong fixed role", mutate: func(plan *control.RendezvousPlan) { plan.Role = "receiver" }},
		{name: "malformed type", mutate: func(plan *control.RendezvousPlan) { plan.Type = "other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneRendezvousPlanMessage(message)
			test.mutate(&candidate)
			if err := runner.acceptRendezvousPlan(candidate, now); err == nil {
				t.Fatal("unsafe same-epoch plan was accepted")
			}
			assertPlanMailboxEmpty(t, runner)
			if runner.planEpoch.Load() != message.PathEpoch {
				t.Fatalf("rejected plan changed remembered epoch to %d", runner.planEpoch.Load())
			}
		})
	}

	if err := runner.acceptRendezvousPlan(message, now.Add(clockSampleMaxAge+time.Nanosecond)); err == nil {
		t.Fatal("same-epoch duplicate bypassed stale authenticated-clock rejection")
	}
	assertPlanMailboxEmpty(t, runner)

	expiredAt := time.Unix(message.ExpiresUnix, 0).Add(6 * time.Second)
	synchronizeClockForTest(runner, lease, expiredAt)
	if err := runner.acceptRendezvousPlan(message, expiredAt); err == nil {
		t.Fatal("same-epoch duplicate bypassed expiry rejection")
	}
	assertPlanMailboxEmpty(t, runner)
}

func TestSameEpochDuplicateRebindsOnlyAcrossFreshSameNamespaceLease(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	runner, oldLease, message, initial := acceptedSameEpochFixture(t, now)

	if err := runner.acceptRendezvousPlan(message, now); err != nil {
		t.Fatalf("exact duplicate in the original lease was not idempotent: %v", err)
	}
	assertPlanMailboxEmpty(t, runner)

	dataCtx, cancelData := context.WithCancel(context.Background())
	defer cancelData()
	relay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(dataCtx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	direct, directPeer := newControlSurvivalConnectionPair()
	if err := mux.ActivateDirect(message.PathEpoch, direct); err != nil {
		t.Fatal(err)
	}
	before := mux.Snapshot()

	runner.endPlanSession(oldLease)
	if err := mux.SendPacket([]byte("direct survives control revocation")); err != nil {
		t.Fatalf("established direct path was interrupted by control revocation: %v", err)
	}
	receiveCtx, cancelReceive := context.WithTimeout(context.Background(), time.Second)
	if _, err := directPeer.ReceiveDatagram(receiveCtx); err != nil {
		cancelReceive()
		t.Fatalf("direct peer did not receive during reconnect: %v", err)
	}
	cancelReceive()

	freshLease := runner.beginPlanSession(edgeTestRelayGeneration)
	defer runner.endPlanSession(freshLease)
	if !freshLease.valid() || freshLease.namespace != oldLease.namespace || freshLease.serial == oldLease.serial {
		t.Fatal("test did not create a fresh same-namespace authenticated lease")
	}
	synchronizeClockForTest(runner, freshLease, now)
	if err := runner.acceptRendezvousPlan(message, now); err != nil {
		t.Fatalf("exact same-epoch plan was not rebound after authentication: %v", err)
	}
	rebound := receiveAuthorizedPlan(t, runner)
	if !rebound.leaseRebind || !samePlanSession(rebound.lease, freshLease) ||
		!sameValidatedPlan(rebound.Plan, initial.Plan) {
		t.Fatalf("fresh delivery did not carry exact rebound authority: epoch=%d lease=%d rebind=%t",
			rebound.PathEpoch, rebound.lease.serial, rebound.leaseRebind)
	}
	if runner.planEpoch.Load() != message.PathEpoch {
		t.Fatalf("authority rebind changed epoch to %d", runner.planEpoch.Load())
	}

	retryLease := rebindActivePlanLease(&initial, rebound, message.PathEpoch, oldLease)
	if !samePlanSession(retryLease, freshLease) || !runner.planAuthorityCurrent(retryLease, message.PathEpoch) {
		t.Fatal("later active-connection failure would not retry under the fresh lease")
	}
	if !runner.activePlanRetryEligible(&rebound, message.PathEpoch, retryLease) {
		t.Fatal("direct worker would not schedule the later failure under rebound authority")
	}
	conflicting := rebound
	conflicting.ProbeKey[0] ^= 0xff
	if got := rebindActivePlanLease(&initial, conflicting, message.PathEpoch, oldLease); !samePlanSession(got, oldLease) {
		t.Fatal("defensive worker check rebound a conflicting same-epoch plan")
	}
	foreign := rebound
	foreign.lease.namespace += "foreign"
	if got := rebindActivePlanLease(&initial, foreign, message.PathEpoch, oldLease); !samePlanSession(got, oldLease) {
		t.Fatal("defensive worker check rebound a foreign namespace")
	}

	after := mux.Snapshot()
	if after.Selected != datapath.SelectedDirect || !after.DirectHealthy ||
		after.DirectEpoch != before.DirectEpoch || after.DirectInstanceID != before.DirectInstanceID {
		t.Fatalf("control authority rebind replaced established direct instance: before=%#v after=%#v", before, after)
	}
	if err := mux.SendPacket([]byte("direct survives authority rebind")); err != nil {
		t.Fatalf("established direct path failed after authority rebind: %v", err)
	}
	receiveCtx, cancelReceive = context.WithTimeout(context.Background(), time.Second)
	defer cancelReceive()
	if _, err := directPeer.ReceiveDatagram(receiveCtx); err != nil {
		t.Fatalf("direct peer did not receive after authority rebind: %v", err)
	}

	if err := runner.acceptRendezvousPlan(message, now); err != nil {
		t.Fatalf("duplicate in fresh lease was not idempotent: %v", err)
	}
	assertPlanMailboxEmpty(t, runner)
}

func TestNamespaceChangeErasesRememberedSameEpochPlan(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	runner, oldLease, _, _ := acceptedSameEpochFixture(t, now)
	runner.endPlanSession(oldLease)

	replacement := runner.beginPlanSession("22222222222222222222222222222222")
	defer runner.endPlanSession(replacement)
	if !replacement.valid() {
		t.Fatal("replacement namespace was not authorized in source-only fixture")
	}
	if runner.planEpoch.Load() != 0 {
		t.Fatalf("replacement namespace retained epoch %d", runner.planEpoch.Load())
	}
	runner.mu.Lock()
	remembered := runner.rememberedPlan
	runner.mu.Unlock()
	if remembered != nil {
		t.Fatal("replacement namespace retained the prior exact plan")
	}
}

func acceptedSameEpochFixture(
	t *testing.T,
	now time.Time,
) (*Runner, planSessionLease, control.RendezvousPlan, authorizedPlan) {
	t.Helper()
	runner := controlSurvivalRunner()
	lease := runner.beginPlanSession(edgeTestRelayGeneration)
	if !lease.valid() {
		t.Fatal("plan session was not authorized")
	}
	t.Cleanup(func() { runner.endPlanSession(lease) })
	synchronizeClockForTest(runner, lease, now)
	message := controlSurvivalPlan(now, edgeTestRelayGeneration, 1)
	if err := runner.acceptRendezvousPlan(message, now); err != nil {
		t.Fatalf("initial plan admission: %v", err)
	}
	return runner, lease, message, receiveAuthorizedPlan(t, runner)
}

func receiveAuthorizedPlan(t *testing.T, runner *Runner) authorizedPlan {
	t.Helper()
	select {
	case plan := <-runner.plans:
		return plan
	case <-time.After(time.Second):
		t.Fatal("authorized plan was not delivered")
		return authorizedPlan{}
	}
}

func assertPlanMailboxEmpty(t *testing.T, runner *Runner) {
	t.Helper()
	select {
	case plan := <-runner.plans:
		t.Fatalf("unexpected duplicate plan delivery at epoch %d", plan.PathEpoch)
	default:
	}
}
