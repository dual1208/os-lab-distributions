package edge

import (
	"context"
	"encoding/hex"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/datapath"
)

// Revoking an authenticated control namespace and accepting a plan must be one
// serializable operation. After endPlanSession returns, no plan authenticated
// by that session may remain actionable, even when heartbeat delivery races
// session teardown.
func TestPlanAdmissionCannotRacePastSessionRevocation(t *testing.T) {
	const iterations = 20_000
	now := time.Unix(1_800_000_000, 0)
	message := adversaryControlPlan(now)
	previousProcs := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previousProcs)

	for iteration := 0; iteration < iterations; iteration++ {
		runner := &Runner{
			cfg: config.Edge{
				Circuit:      "campus",
				Generation:   "edge-a-generation",
				Site:         "site-a",
				DeploymentID: edgeTestDeploymentID,
			},
			version: "test",
			plans:   make(chan authorizedPlan, 1),
		}
		namespace := runner.beginPlanSession(edgeTestRelayGeneration)
		synchronizeClockForTest(runner, namespace, now)
		start := make(chan struct{})
		var joined sync.WaitGroup
		joined.Add(2)
		go func() {
			defer joined.Done()
			<-start
			_ = runner.acceptRendezvousPlan(message, now)
		}()
		go func() {
			defer joined.Done()
			<-start
			runner.endPlanSession(namespace)
		}()
		close(start)
		joined.Wait()

		runner.mu.Lock()
		revoked := runner.relayGeneration == ""
		runner.mu.Unlock()
		if !revoked {
			t.Fatalf("iteration %d: authenticated namespace was not revoked", iteration)
		}
		select {
		case plan := <-runner.plans:
			t.Fatalf("iteration %d: revoked session left path epoch %d actionable", iteration, plan.PathEpoch)
		default:
		}
	}
}

// A failed namespace transition must remain blocked across control reconnects.
// Otherwise the first attempt can install the new namespace while withholding
// its lease, and a second attempt can mistake that namespace for fully retired
// and admit plans while the old direct path is still the only healthy path.
func TestBlockedNamespaceCannotBypassRetirementOnReconnect(t *testing.T) {
	runner := controlSurvivalRunner()
	oldLease := runner.beginPlanSession(edgeTestRelayGeneration)
	defer runner.endPlanSession(oldLease)
	runner.planEpoch.Store(9)

	dataCtx, cancelData := context.WithCancel(context.Background())
	defer cancelData()
	relay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(dataCtx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	direct, _ := newControlSurvivalConnectionPair()
	if err := mux.ActivateDirect(9, direct); err != nil {
		t.Fatal(err)
	}
	runner.setPathMux(mux)
	defer runner.setPathMux(nil)
	if err := relay.Close("test relay outage"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for mux.Snapshot().RelayHealthy && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if mux.Snapshot().RelayHealthy {
		t.Fatal("relay outage was not observed")
	}

	newGeneration := "44444444444444444444444444444444"
	if lease := runner.authorizePlanSession(newGeneration, true); lease.serial != 0 {
		t.Fatal("initial unsafe namespace transition was admitted")
	}
	if lease := runner.authorizePlanSession(newGeneration, true); lease.serial != 0 {
		t.Fatal("control reconnect bypassed the pending direct retirement")
	}
	snapshot := mux.Snapshot()
	if !snapshot.DirectHealthy || snapshot.RelayHealthy || snapshot.Selected != datapath.SelectedDirect {
		t.Fatalf("blocked retry changed the established data path: %#v", snapshot)
	}
}

// Path epochs are scoped by the exact authenticated control-session lease, not
// just by their numeric value. Revocation must permanently stale an in-flight
// activation even if a later session or namespace reuses the same path epoch.
func TestRevokedPlanSessionCannotRegainActivationThroughEpochABA(t *testing.T) {
	const epoch = uint64(17)
	runner := controlSurvivalRunner()
	oldLease := runner.beginPlanSession(edgeTestRelayGeneration)
	runner.planEpoch.Store(epoch)
	activation := &muxActivation{
		runner: runner, mux: &datapath.Mux{}, connection: &quicDataConnection{}, epoch: epoch, lease: oldLease,
	}
	if !activation.current(epoch) {
		t.Fatal("activation was not current in its originating authenticated session")
	}

	runner.endPlanSession(oldLease)
	if activation.current(epoch) {
		t.Fatal("revoked activation remained current after its control session ended")
	}

	newLease := runner.beginPlanSession(edgeTestRelayGeneration)
	defer runner.endPlanSession(newLease)
	runner.planEpoch.Store(epoch)
	if activation.current(epoch) {
		t.Fatal("same-namespace reconnect revived a revoked activation by reusing its epoch")
	}

	runner.endPlanSession(newLease)
	replacementGeneration := "55555555555555555555555555555555"
	replacementLease := runner.beginPlanSession(replacementGeneration)
	defer runner.endPlanSession(replacementLease)
	runner.planEpoch.Store(epoch)
	if activation.current(epoch) {
		t.Fatal("replacement namespace revived a revoked activation by reusing its epoch")
	}
}

func TestRevokedPlanSessionRejectsEveryActivationPhase(t *testing.T) {
	const epoch = uint64(23)
	runner := controlSurvivalRunner()
	oldLease := runner.beginPlanSession(edgeTestRelayGeneration)
	runner.planEpoch.Store(epoch)
	activation := &muxActivation{
		runner: runner, mux: &datapath.Mux{}, connection: &quicDataConnection{}, epoch: epoch, lease: oldLease,
	}
	if !activation.current(epoch) {
		t.Fatal("activation was not current before session revocation")
	}

	runner.endPlanSession(oldLease)
	replacementLease := runner.beginPlanSession(edgeTestRelayGeneration)
	defer runner.endPlanSession(replacementLease)
	runner.planEpoch.Store(epoch)
	phases := []struct {
		name string
		run  func(uint64) error
	}{
		{name: "prepare", run: activation.PrepareDirect},
		{name: "select", run: activation.SelectDirect},
		{name: "commit", run: activation.CommitDirect},
	}
	for _, phase := range phases {
		t.Run(phase.name, func(t *testing.T) {
			if err := phase.run(epoch); !errors.Is(err, datapath.ErrStalePath) {
				t.Fatalf("revoked activation phase returned %v", err)
			}
		})
	}
}

func adversaryControlPlan(now time.Time) control.RendezvousPlan {
	return control.RendezvousPlan{
		Type:            "rendezvous-plan",
		Circuit:         "campus",
		Version:         "test",
		DeploymentID:    edgeTestDeploymentID,
		RelayGeneration: edgeTestRelayGeneration,
		Generation:      "edge-a-generation",
		PeerGeneration:  "edge-b-generation",
		Session:         hex.EncodeToString([]byte("0123456789abcdef")),
		ProbeKey:        hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		Role:            "sender",
		Attempt:         1,
		PathEpoch:       1,
		StartUnix:       now.Add(time.Second).Unix(),
		ExpiresUnix:     now.Add(45 * time.Second).Unix(),
		Candidates:      []string{"203.0.113.10:41000"},
	}
}
