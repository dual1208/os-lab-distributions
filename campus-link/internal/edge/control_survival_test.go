package edge

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/config"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/datapath"
)

func TestControlFailureDoesNotStopActiveDirectDataPath(t *testing.T) {
	dataCtx, cancelData := context.WithCancel(context.Background())
	defer cancelData()

	relay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(dataCtx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	direct, directPeer := newControlSurvivalConnectionPair()
	if err := mux.ActivateDirect(1, direct); err != nil {
		t.Fatal(err)
	}

	tunRead, tunWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer tunRead.Close()
	defer tunWrite.Close()

	runner := &Runner{cfg: config.Edge{Prefix: "10.81.0.0/24", RemotePrefix: "10.82.0.0/24", MTU: 1200}}
	controlErr := make(chan error, 1)
	dispatcherErr := make(chan error)
	bridgeDone := make(chan error, 1)
	go func() {
		bridgeDone <- runner.bridge(dataCtx, mux, tunRead, controlErr, dispatcherErr)
	}()

	controlErr <- errors.New("authenticated control session unavailable")
	select {
	case err := <-bridgeDone:
		t.Fatalf("control-only outage stopped an authenticated direct data path: %v", err)
	case <-time.After(75 * time.Millisecond):
	}

	snapshot := mux.Snapshot()
	if snapshot.Selected != datapath.SelectedDirect || !snapshot.DirectHealthy {
		t.Fatalf("direct path changed after control-only outage: %#v", snapshot)
	}
	payload := []byte("data path remains independent of broker reachability")
	if err := mux.SendPacket(payload); err != nil {
		t.Fatalf("direct send after control-only outage: %v", err)
	}
	receiveCtx, cancelReceive := context.WithTimeout(context.Background(), time.Second)
	defer cancelReceive()
	wire, err := directPeer.ReceiveDatagram(receiveCtx)
	if err != nil {
		t.Fatalf("direct peer did not receive after control-only outage: %v", err)
	}
	if len(wire) != len(payload)+datapath.WireOverhead {
		t.Fatalf("unexpected direct wire length: got %d want %d", len(wire), len(payload)+datapath.WireOverhead)
	}

	cancelData()
	select {
	case err := <-bridgeDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("bridge shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("bridge did not stop with the data lifetime")
	}
}

func TestControlSessionShutdownRevokesAndJoinsWithoutCancelingData(t *testing.T) {
	runner := controlSurvivalRunner()
	lease := runner.beginPlanSession(edgeTestRelayGeneration)
	controlCtx, cancelControl := context.WithCancel(context.Background())
	controlDone := make(chan struct{})
	close(controlDone)
	session := &authenticatedControlSession{cancel: cancelControl, done: controlDone, planLease: lease}

	dataCtx, cancelData := context.WithCancel(context.Background())
	defer cancelData()
	relay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(dataCtx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	direct, directPeer := newControlSurvivalConnectionPair()
	if err := mux.ActivateDirect(1, direct); err != nil {
		t.Fatal(err)
	}

	session.shutdown(runner)
	if controlCtx.Err() == nil {
		t.Fatal("control session context remained active after shutdown")
	}
	if dataCtx.Err() != nil {
		t.Fatalf("control session shutdown canceled the data lifetime: %v", dataCtx.Err())
	}
	now := time.Unix(1_800_000_000, 0)
	if err := runner.acceptRendezvousPlan(controlSurvivalPlan(now, edgeTestRelayGeneration, 1), now); err == nil {
		t.Fatal("revoked control session retained plan authority")
	}
	if err := mux.SendPacket([]byte("control-independent data")); err != nil {
		t.Fatalf("direct send after control shutdown: %v", err)
	}
	receiveCtx, cancelReceive := context.WithTimeout(context.Background(), time.Second)
	defer cancelReceive()
	if _, err := directPeer.ReceiveDatagram(receiveCtx); err != nil {
		t.Fatalf("direct path stopped with control session: %v", err)
	}
}

func TestControlReconnectMustReauthenticateNamespaceBeforePlansResume(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
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
	first := controlSurvivalPlan(now, edgeTestRelayGeneration, 1)
	if err := runner.acceptRendezvousPlan(first, now); err != nil {
		t.Fatal(err)
	}
	if got := <-runner.plans; got.PathEpoch != 1 {
		t.Fatalf("unexpected initial plan epoch: %d", got.PathEpoch)
	}

	dataCtx, cancelData := context.WithCancel(context.Background())
	defer cancelData()
	relay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(dataCtx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	direct, directPeer := newControlSurvivalConnectionPair()
	if err := mux.ActivateDirect(1, direct); err != nil {
		t.Fatal(err)
	}

	runner.endPlanSession(namespace)
	second := controlSurvivalPlan(now, edgeTestRelayGeneration, 2)
	if err := runner.acceptRendezvousPlan(second, now); err == nil {
		t.Fatal("plan accepted while no authenticated control namespace was active")
	}
	if snapshot := mux.Snapshot(); snapshot.Selected != datapath.SelectedDirect || !snapshot.DirectHealthy {
		t.Fatalf("revoking plan authority stopped the established direct path: %#v", snapshot)
	}
	if err := mux.SendPacket([]byte("still direct")); err != nil {
		t.Fatalf("direct path failed while control reconnects: %v", err)
	}
	receiveCtx, cancelReceive := context.WithTimeout(context.Background(), time.Second)
	defer cancelReceive()
	if _, err := directPeer.ReceiveDatagram(receiveCtx); err != nil {
		t.Fatalf("direct peer did not receive during control reconnect: %v", err)
	}

	reauthenticated := runner.beginPlanSession(edgeTestRelayGeneration)
	defer runner.endPlanSession(reauthenticated)
	synchronizeClockForTest(runner, reauthenticated, now)
	if reauthenticated.namespace != namespace.namespace || reauthenticated.serial == namespace.serial {
		t.Fatal("same authenticated relay generation produced a different namespace")
	}
	foreign := controlSurvivalPlan(now, "11111111111111111111111111111111", 2)
	if err := runner.acceptRendezvousPlan(foreign, now); err == nil {
		t.Fatal("plan from a non-authenticated namespace was accepted after reconnect")
	}
	if err := runner.acceptRendezvousPlan(second, now); err != nil {
		t.Fatalf("plan was not accepted after namespace re-authentication: %v", err)
	}
	if got := <-runner.plans; got.PathEpoch != 2 {
		t.Fatalf("unexpected post-reconnect plan epoch: %d", got.PathEpoch)
	}
}

func TestPlanAuthorityRequiresValidatedUDPBinding(t *testing.T) {
	runner := controlSurvivalRunner()
	if lease := runner.authorizePlanSession(edgeTestRelayGeneration, false); lease.serial != 0 {
		t.Fatal("plan authority was granted before authenticated UDP binding")
	}
	now := time.Unix(1_800_000_000, 0)
	if err := runner.acceptRendezvousPlan(controlSurvivalPlan(now, edgeTestRelayGeneration, 1), now); err == nil {
		t.Fatal("plan was actionable before authenticated UDP binding")
	}
	lease := runner.authorizePlanSession(edgeTestRelayGeneration, true)
	if lease.serial == 0 {
		t.Fatal("plan authority was not granted after authenticated UDP binding")
	}
	defer runner.endPlanSession(lease)
}

func TestControlRetryDelayIsMonotonicAndBounded(t *testing.T) {
	initial, maximum := 100*time.Millisecond, 800*time.Millisecond
	want := []time.Duration{initial, 2 * initial, 4 * initial, maximum, maximum}
	for attempt, expected := range want {
		if got := controlRetryDelay(uint(attempt), initial, maximum); got != expected {
			t.Fatalf("attempt %d delay=%s want=%s", attempt, got, expected)
		}
	}
	previous := time.Duration(0)
	for attempt := uint(0); attempt < 128; attempt++ {
		delay := controlRetryDelay(attempt, initial, maximum)
		if delay < initial || delay > maximum {
			t.Fatalf("attempt %d delay outside bounds: %s", attempt, delay)
		}
		if delay < previous {
			t.Fatalf("attempt %d delay regressed from %s to %s", attempt, previous, delay)
		}
		previous = delay
	}
}

func TestControlRetryJitterStaysWithinBoundAndWaitCancels(t *testing.T) {
	delay := 800 * time.Millisecond
	floor := delay - delay/4
	if got := jitterRetryDelay(delay, bytes.NewReader(make([]byte, 8))); got != floor {
		t.Fatalf("minimum jitter=%s want=%s", got, floor)
	}
	span := delay - floor
	sample := make([]byte, 8)
	binary.BigEndian.PutUint64(sample, uint64(span))
	if got := jitterRetryDelay(delay, bytes.NewReader(sample)); got != delay {
		t.Fatalf("maximum jitter=%s want=%s", got, delay)
	}
	if got := jitterRetryDelay(delay, bytes.NewReader(nil)); got != delay {
		t.Fatalf("entropy failure delay=%s want conservative cap=%s", got, delay)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if err := waitControlRetry(ctx, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled retry wait returned %v", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("canceled retry wait took %s", elapsed)
	}
}

func TestChangedControlNamespaceRetiresOldDirectBeforeAdmission(t *testing.T) {
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

	newGeneration := "22222222222222222222222222222222"
	newLease := runner.authorizePlanSession(newGeneration, true)
	if newLease.serial == 0 {
		t.Fatal("healthy relay could not accept the authenticated replacement namespace")
	}
	defer runner.endPlanSession(newLease)
	snapshot := mux.Snapshot()
	if snapshot.DirectHealthy || !snapshot.RelayHealthy || snapshot.Selected != datapath.SelectedRelay {
		t.Fatalf("old-namespace direct was not retired safely: %#v", snapshot)
	}
	if runner.planEpoch.Load() != 0 {
		t.Fatalf("new namespace inherited old path epoch %d", runner.planEpoch.Load())
	}
	runner.mu.Lock()
	blocked := runner.blockedPlanNamespace
	runner.mu.Unlock()
	if blocked != "" {
		t.Fatal("safe namespace transition remained blocked")
	}
}

func TestChangedControlNamespaceFailsClosedWhenOldDirectCannotRetire(t *testing.T) {
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

	newGeneration := "33333333333333333333333333333333"
	if lease := runner.authorizePlanSession(newGeneration, true); lease.serial != 0 {
		t.Fatal("replacement namespace admitted while the old direct was the only healthy path")
	}
	if lease := runner.authorizePlanSession(newGeneration, true); lease.serial != 0 {
		t.Fatal("blocked replacement namespace bypassed retirement on a later authorization attempt")
	}
	snapshot := mux.Snapshot()
	if !snapshot.DirectHealthy || snapshot.Selected != datapath.SelectedDirect {
		t.Fatalf("fail-closed namespace transition interrupted the established direct path: %#v", snapshot)
	}
	if runner.planEpoch.Load() != 0 {
		t.Fatalf("prior namespace remained actionable at epoch %d", runner.planEpoch.Load())
	}
	runner.mu.Lock()
	blocked := runner.blockedPlanNamespace
	runner.mu.Unlock()
	if blocked == "" {
		t.Fatal("unsafe namespace transition did not retain its fail-closed marker")
	}
	now := time.Unix(1_800_000_000, 0)
	if err := runner.acceptRendezvousPlan(controlSurvivalPlan(now, newGeneration, 1), now); err == nil {
		t.Fatal("plan admitted after fail-closed namespace transition")
	}
}

func controlSurvivalRunner() *Runner {
	return &Runner{
		cfg: config.Edge{
			Circuit:      "campus",
			Generation:   "edge-a-generation",
			Site:         "site-a",
			DeploymentID: edgeTestDeploymentID,
		},
		version: "test",
		plans:   make(chan authorizedPlan, 1),
	}
}

func controlSurvivalPlan(now time.Time, relayGeneration string, epoch uint64) control.RendezvousPlan {
	return control.RendezvousPlan{
		Type:            "rendezvous-plan",
		Circuit:         "campus",
		Version:         "test",
		DeploymentID:    edgeTestDeploymentID,
		RelayGeneration: relayGeneration,
		Generation:      "edge-a-generation",
		PeerGeneration:  "edge-b-generation",
		Session:         hex.EncodeToString([]byte("0123456789abcdef")),
		ProbeKey:        hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		Role:            "sender",
		Attempt:         1,
		PathEpoch:       epoch,
		StartUnix:       now.Add(time.Second).Unix(),
		ExpiresUnix:     now.Add(45 * time.Second).Unix(),
		Candidates:      []string{"203.0.113.10:41000"},
	}
}

type controlSurvivalConnection struct {
	inbound chan []byte
	peer    *controlSurvivalConnection
	closed  chan struct{}
	once    sync.Once
}

func newControlSurvivalConnectionPair() (*controlSurvivalConnection, *controlSurvivalConnection) {
	a := &controlSurvivalConnection{inbound: make(chan []byte, 8), closed: make(chan struct{})}
	b := &controlSurvivalConnection{inbound: make(chan []byte, 8), closed: make(chan struct{})}
	a.peer, b.peer = b, a
	return a, b
}

func (c *controlSurvivalConnection) SendDatagram(packet []byte) error {
	copyOfPacket := append([]byte(nil), packet...)
	select {
	case <-c.closed:
		return net.ErrClosed
	case <-c.peer.closed:
		return net.ErrClosed
	case c.peer.inbound <- copyOfPacket:
		return nil
	}
}

func (c *controlSurvivalConnection) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-c.closed:
		return nil, net.ErrClosed
	case packet := <-c.inbound:
		return packet, nil
	}
}

func (c *controlSurvivalConnection) Close(string) error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
