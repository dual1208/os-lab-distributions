package edge

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/datapath"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/identity"
)

// relayRecoverySupervisor is the narrow runtime seam required to test relay
// recovery without real addresses or credentials. reconnect must return only a
// fully authenticated, peer-authorized, capacity-validated relay connection.
type relayRecoverySupervisor interface {
	superviseRelay(
		context.Context,
		*datapath.Mux,
		func(context.Context) (relayPathCandidate, error),
	) error
}

func authenticatedRelayCandidate(connection datapath.Connection) relayPathCandidate {
	now := time.Now()
	return relayPathCandidate{
		connection: connection,
		peer:       identity.Verified{NotAfter: now.Add(time.Hour), PinSlot: 0},
		cutoff:     now.Add(30 * time.Minute),
		liveness:   context.Background(),
		state:      &relayCandidateState{},
	}
}

func TestProductionRelayMuxRequiresDirectAndNeverEmitsTUNPayload(t *testing.T) {
	runner := controlSurvivalRunner()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay, peer := newControlSurvivalConnectionPair()
	mux, err := runner.newRelayMux(ctx, 1200, authenticatedRelayCandidate(relay))
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	snapshot := mux.Snapshot()
	if !snapshot.DirectRequired || snapshot.Selected != datapath.SelectedNone || !snapshot.RelayHealthy {
		t.Fatalf("production mux selected broker path: %#v", snapshot)
	}
	sendCtx, cancelSend := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancelSend()
	if err := mux.SendPacketContext(sendCtx, []byte{0x45}); !errors.Is(err, datapath.ErrNoHealthyPath) {
		t.Fatalf("pre-direct production send returned %v", err)
	}
	select {
	case wire := <-peer.inbound:
		t.Fatalf("production TUN payload traversed broker: %x", wire)
	default:
	}
	if snapshot := mux.Snapshot(); snapshot.Counters.RelaySent != 0 || snapshot.Counters.RelayReceived != 0 {
		t.Fatalf("production broker payload counters advanced: %#v", snapshot.Counters)
	}
}

func TestRelayCandidateCrossingCutoffBeforeCommitCannotFlapHealthy(t *testing.T) {
	runner := controlSurvivalRunner()
	dataCtx, cancelData := context.WithCancel(context.Background())
	defer cancelData()
	oldRelay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(dataCtx, 1200, oldRelay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	if err := oldRelay.Close("simulate relay loss before stale reconnect"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for mux.Snapshot().RelayHealthy && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if mux.Snapshot().RelayHealthy {
		t.Fatal("relay loss was not observed")
	}

	replacement, _ := newControlSurvivalConnectionPair()
	candidate := authenticatedRelayCandidate(replacement)
	candidate.now = func() time.Time { return candidate.cutoff }
	if _, err := runner.commitRelayCandidate(mux, candidate); !errors.Is(err, identity.ErrCertificateCutoff) {
		t.Fatalf("candidate crossing cutoff at commit returned %v", err)
	}
	snapshot := mux.Snapshot()
	if snapshot.RelayHealthy || snapshot.Selected != datapath.SelectedNone || snapshot.RelayInstanceID != 1 {
		t.Fatalf("expired reconnect briefly replaced the failed relay: %#v", snapshot)
	}
	select {
	case <-replacement.closed:
	case <-time.After(time.Second):
		t.Fatal("expired relay candidate was not closed")
	}
}

func TestRelayCommitPublishesExactSelectedIdentityAtomically(t *testing.T) {
	runner := controlSurvivalRunner()
	dataCtx, cancelData := context.WithCancel(context.Background())
	defer cancelData()
	oldRelay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(dataCtx, 1200, oldRelay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	oldPeer := identity.Verified{NotAfter: time.Now().Add(time.Hour), PinSlot: 0}
	oldSnapshot := mux.Snapshot()
	runner.mu.Lock()
	runner.pathMux = mux
	runner.bindPathIdentityLocked(mux, datapath.SelectedRelay, oldSnapshot.RelayInstanceID, oldPeer)
	runner.mu.Unlock()
	if err := oldRelay.Close("simulate relay replacement"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for mux.Snapshot().RelayHealthy && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if mux.Snapshot().RelayHealthy {
		t.Fatal("relay loss was not observed")
	}

	replacement, _ := newControlSurvivalConnectionPair()
	candidate := authenticatedRelayCandidate(replacement)
	candidate.peer.PinSlot = 1
	instanceID, err := runner.commitRelayCandidate(mux, candidate)
	if err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	snapshot := mux.Snapshot()
	peer := selectedPeerData(mux, snapshot, runner.pathPeerData)
	bindingCount := len(runner.pathPeerData)
	runner.mu.Unlock()
	if snapshot.Selected != datapath.SelectedRelay || !snapshot.RelayHealthy || snapshot.RelayInstanceID != instanceID {
		t.Fatalf("replacement relay was not selected exactly: %#v", snapshot)
	}
	if peer.PinSlot != candidate.peer.PinSlot || !peer.NotAfter.Equal(candidate.peer.NotAfter) {
		t.Fatalf("selected replacement was visible without its exact identity: %#v", peer)
	}
	if bindingCount != 1 {
		t.Fatalf("retired relay identity was not bounded away: bindings=%d", bindingCount)
	}
}

func TestControlOfflineRelayRestartRecoversWarmFallbackWithoutClosingDirect(t *testing.T) {
	runner := controlSurvivalRunner()
	supervisor, ok := any(runner).(relayRecoverySupervisor)
	if !ok {
		t.Fatal("edge has no relay recovery supervisor; control reconnect cannot restore a failed warm relay")
	}

	dataCtx, cancelData := context.WithCancel(context.Background())
	defer cancelData()
	oldRelay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(dataCtx, 1200, oldRelay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	direct, directPeer := newControlSurvivalConnectionPair()
	if err := mux.ActivateDirect(19, direct); err != nil {
		t.Fatal(err)
	}

	// Revoke broker authority first. Data lifetime and an established direct
	// connection must remain independent while gz control/UDP/QUIC restart.
	lease := runner.beginPlanSession(edgeTestRelayGeneration)
	controlCtx, cancelControl := context.WithCancel(context.Background())
	controlDone := make(chan struct{})
	close(controlDone)
	(&authenticatedControlSession{cancel: cancelControl, done: controlDone, planLease: lease}).shutdown(runner)
	if controlCtx.Err() == nil {
		t.Fatal("control test session was not shut down")
	}

	replacement, replacementPeer := newControlSurvivalConnectionPair()
	dialStarted := make(chan struct{})
	allowAuthenticatedReplacement := make(chan struct{})
	var reconnectCalls atomic.Uint64
	reconnect := func(ctx context.Context) (relayPathCandidate, error) {
		if reconnectCalls.Add(1) == 1 {
			close(dialStarted)
		}
		select {
		case <-ctx.Done():
			return relayPathCandidate{}, context.Cause(ctx)
		case <-allowAuthenticatedReplacement:
			return authenticatedRelayCandidate(replacement), nil
		}
	}
	supervisorCtx, cancelSupervisor := context.WithCancel(dataCtx)
	supervisorDone := make(chan error, 1)
	go func() { supervisorDone <- supervisor.superviseRelay(supervisorCtx, mux, reconnect) }()
	defer func() {
		cancelSupervisor()
		select {
		case err := <-supervisorDone:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("relay supervisor shutdown: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("relay supervisor did not stop with the data lifetime")
		}
	}()

	if err := oldRelay.Close("simulated relay restart"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("relay loss did not start a bounded replacement attempt")
	}
	if snapshot := mux.Snapshot(); snapshot.RelayHealthy || !snapshot.DirectHealthy || snapshot.Selected != datapath.SelectedDirect {
		t.Fatalf("relay outage did not preserve only the established direct path: %#v", snapshot)
	}
	if err := mux.SendPacket([]byte("direct survives broker restart")); err != nil {
		t.Fatal(err)
	}
	receiveCtx, cancelReceive := context.WithTimeout(context.Background(), time.Second)
	if _, err := directPeer.ReceiveDatagram(receiveCtx); err != nil {
		cancelReceive()
		t.Fatalf("direct traffic stopped while all broker planes were unavailable: %v", err)
	}
	cancelReceive()

	close(allowAuthenticatedReplacement)
	waitEdgeRelayHealthy(t, mux)
	if snapshot := mux.Snapshot(); !snapshot.DirectHealthy || snapshot.Selected != datapath.SelectedDirect {
		t.Fatalf("warm relay recovery replaced or demoted direct: %#v", snapshot)
	}
	if reconnectCalls.Load() != 1 {
		t.Fatalf("successful relay recovery made %d reconnect calls, want 1", reconnectCalls.Load())
	}

	// Failure of direct after recovery must deliver one copy through the new
	// warm relay, never through the retired relay instance.
	if err := direct.Close("simulated direct failure"); err != nil {
		t.Fatal(err)
	}
	waitEdgeSelectedRelay(t, mux)
	if err := mux.SendPacket([]byte("single recovered-relay copy")); err != nil {
		t.Fatal(err)
	}
	relayReceiveCtx, cancelRelayReceive := context.WithTimeout(context.Background(), time.Second)
	if _, err := replacementPeer.ReceiveDatagram(relayReceiveCtx); err != nil {
		cancelRelayReceive()
		t.Fatalf("replacement relay did not carry fallback traffic: %v", err)
	}
	cancelRelayReceive()
	if len(replacementPeer.inbound) != 0 {
		t.Fatal("replacement relay received duplicate tunnel packets")
	}
}

func TestRelaySupervisorRetriesTransientFailuresWithoutDisturbingDirect(t *testing.T) {
	runner := controlSurvivalRunner()
	dataCtx, cancelData := context.WithCancel(context.Background())
	defer cancelData()
	oldRelay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(dataCtx, 1200, oldRelay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	direct, directPeer := newControlSurvivalConnectionPair()
	if err := mux.ActivateDirect(31, direct); err != nil {
		t.Fatal(err)
	}
	replacement, _ := newControlSurvivalConnectionPair()
	var reconnectCalls atomic.Uint64
	reconnect := func(context.Context) (relayPathCandidate, error) {
		if reconnectCalls.Add(1) < 3 {
			return relayPathCandidate{}, errors.New("transient authenticated relay outage")
		}
		return authenticatedRelayCandidate(replacement), nil
	}
	supervisorCtx, cancelSupervisor := context.WithCancel(dataCtx)
	supervisorDone := make(chan error, 1)
	go func() { supervisorDone <- runner.superviseRelay(supervisorCtx, mux, reconnect) }()

	if err := oldRelay.Close("simulated transient relay outage"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for (!mux.Snapshot().RelayHealthy || reconnectCalls.Load() < 3) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if reconnectCalls.Load() != 3 || !mux.Snapshot().RelayHealthy {
		t.Fatalf("bounded recovery did not succeed on attempt three: calls=%d snapshot=%#v", reconnectCalls.Load(), mux.Snapshot())
	}
	if snapshot := mux.Snapshot(); snapshot.Selected != datapath.SelectedDirect || !snapshot.DirectHealthy {
		t.Fatalf("transient relay retries disturbed direct: %#v", snapshot)
	}
	if err := mux.SendPacket([]byte("direct remains selected across retries")); err != nil {
		t.Fatal(err)
	}
	receiveCtx, cancelReceive := context.WithTimeout(context.Background(), time.Second)
	if _, err := directPeer.ReceiveDatagram(receiveCtx); err != nil {
		cancelReceive()
		t.Fatalf("direct traffic failed after relay retries: %v", err)
	}
	cancelReceive()

	cancelSupervisor()
	select {
	case err := <-supervisorDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("relay supervisor cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay supervisor did not stop after retry test")
	}
}

func waitEdgeRelayHealthy(t *testing.T, mux *datapath.Mux) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if mux.Snapshot().RelayHealthy {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("replacement relay did not become healthy: %#v", mux.Snapshot())
}

func waitEdgeSelectedRelay(t *testing.T, mux *datapath.Mux) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		snapshot := mux.Snapshot()
		if snapshot.RelayHealthy && !snapshot.DirectHealthy && snapshot.Selected == datapath.SelectedRelay {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("direct failure did not select recovered relay: %#v", mux.Snapshot())
}
