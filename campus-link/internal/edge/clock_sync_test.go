package edge

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
	"github.com/dual1208/os-lab-distributions/campus-link/internal/datapath"
)

func TestAuthenticatedClockOffsetBoundsAcceptPositiveAndNegativeSkew(t *testing.T) {
	for _, skew := range []time.Duration{-750 * time.Millisecond, 750 * time.Millisecond} {
		t.Run(skew.String(), func(t *testing.T) {
			exchange, ack, received := clockFixture(skew, 20*time.Millisecond, 5*time.Millisecond, 20*time.Millisecond)
			measurement, err := evaluateClockExchange(exchange, ack, received)
			if err != nil {
				t.Fatalf("bounded skew rejected: %v", err)
			}
			if measurement.absoluteOffset != 750*time.Millisecond || measurement.uncertainty != 20*time.Millisecond {
				t.Fatalf("measurement=%#v", measurement)
			}
		})
	}
	for _, skew := range []time.Duration{-1001 * time.Millisecond, 1001 * time.Millisecond} {
		t.Run("reject_"+skew.String(), func(t *testing.T) {
			exchange, ack, received := clockFixture(skew, time.Millisecond, time.Millisecond, time.Millisecond)
			if _, err := evaluateClockExchange(exchange, ack, received); !errors.Is(err, errInvalidClockSample) {
				t.Fatalf("out-of-bound skew returned %v", err)
			}
		})
	}
}

func TestRuntimeClockCaptureProducesCanonicalExchange(t *testing.T) {
	runner := controlSurvivalRunner()
	lease := runner.beginPlanSession(edgeTestRelayGeneration)
	defer runner.endPlanSession(lease)
	exchange, err := newClockExchange(1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := exchange.heartbeat()
	ack := validClockAckForTest(heartbeat)
	time.Sleep(time.Millisecond)
	receivedAt := time.Now()
	if _, err := evaluateClockExchange(exchange, ack, receivedAt); err != nil {
		t.Fatalf("local runtime clock exchange rejected: %v", err)
	}
	if err := runner.recordClockSample(lease, exchange, ack, receivedAt); err != nil {
		t.Fatalf("local runtime clock record rejected: %v", err)
	}
}

func TestAuthenticatedClockDelayAsymmetryUsesConservativeInterval(t *testing.T) {
	for _, test := range []struct {
		name     string
		skew     time.Duration
		uplink   time.Duration
		downlink time.Duration
		valid    bool
	}{
		{name: "bounded uplink asymmetry", skew: 900 * time.Millisecond, uplink: 90 * time.Millisecond, downlink: time.Millisecond, valid: true},
		{name: "bounded downlink asymmetry", skew: -900 * time.Millisecond, uplink: time.Millisecond, downlink: 90 * time.Millisecond, valid: true},
		{name: "point estimate cannot hide upper overflow", skew: 950 * time.Millisecond, uplink: 100 * time.Millisecond, downlink: time.Millisecond},
		{name: "point estimate cannot hide lower overflow", skew: -950 * time.Millisecond, uplink: time.Millisecond, downlink: 100 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			exchange, ack, received := clockFixture(test.skew, test.uplink, 2*time.Millisecond, test.downlink)
			_, err := evaluateClockExchange(exchange, ack, received)
			if test.valid && err != nil {
				t.Fatalf("conservatively bounded interval rejected: %v", err)
			}
			if !test.valid && !errors.Is(err, errInvalidClockSample) {
				t.Fatalf("unprovable interval returned %v", err)
			}
		})
	}
}

func TestAuthenticatedClockRejectsReplayMismatchOverflowAndWallRollback(t *testing.T) {
	exchange, valid, received := clockFixture(0, 10*time.Millisecond, time.Millisecond, 10*time.Millisecond)
	tests := map[string]func(*clockExchange, *control.HeartbeatAck, *time.Time){
		"sequence replay": func(_ *clockExchange, ack *control.HeartbeatAck, _ *time.Time) { ack.Sequence-- },
		"sample mismatch": func(_ *clockExchange, ack *control.HeartbeatAck, _ *time.Time) { ack.EdgeMonotonicNano++ },
		"sample overflow": func(_ *clockExchange, ack *control.HeartbeatAck, _ *time.Time) {
			ack.EdgeMonotonicNano = control.MaxMonotonicSample + 1
		},
		"timestamp overflow": func(_ *clockExchange, ack *control.HeartbeatAck, _ *time.Time) {
			ack.RelaySendUnixNano = int64(^uint64(0) >> 1)
		},
		"relay wall rollback": func(_ *clockExchange, ack *control.HeartbeatAck, _ *time.Time) {
			ack.RelaySendUnixNano = ack.RelayReceiveUnixNano - 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidateExchange, candidateAck, candidateReceived := exchange, valid, received
			mutate(&candidateExchange, &candidateAck, &candidateReceived)
			if _, err := evaluateClockExchange(candidateExchange, candidateAck, candidateReceived); !errors.Is(err, errInvalidClockSample) {
				t.Fatalf("malformed sample returned %v", err)
			}
		})
	}
	if _, err := evaluateClockExchangeCaptured(exchange, valid, received, exchange.edgeWall-1); !errors.Is(err, errInvalidClockSample) {
		t.Fatalf("edge wall rollback returned %v", err)
	}
}

func TestPlanAdmissionRequiresFreshAuthenticatedClockSample(t *testing.T) {
	now := clockTestBase()
	runner := controlSurvivalRunner()
	lease := runner.beginPlanSession(edgeTestRelayGeneration)
	defer runner.endPlanSession(lease)
	plan := controlSurvivalPlan(now, edgeTestRelayGeneration, 1)
	if err := runner.acceptRendezvousPlan(plan, now); err == nil {
		t.Fatal("plan admitted before an authenticated clock sample")
	}
	synchronizeClockForTest(runner, lease, now)
	runner.mu.Lock()
	if !runner.clockStatusCurrentLocked(now) || runner.clockStatusCurrentLocked(now.Add(clockSampleMaxAge+time.Nanosecond)) {
		runner.mu.Unlock()
		t.Fatal("sanitized synchronization status did not obey the sample freshness bound")
	}
	runner.mu.Unlock()
	if err := runner.acceptRendezvousPlan(plan, now); err != nil {
		t.Fatalf("plan rejected with a current authenticated clock sample: %v", err)
	}
	<-runner.plans
	plan.PathEpoch++
	if err := runner.acceptRendezvousPlan(plan, now.Add(clockSampleMaxAge+time.Nanosecond)); err == nil {
		t.Fatal("plan admitted after the authenticated clock sample became stale")
	}
}

func TestRepeatedInvalidClockSamplesRevokeOnlyPlanAuthority(t *testing.T) {
	runner := controlSurvivalRunner()
	lease := runner.beginPlanSession(edgeTestRelayGeneration)

	dataCtx, cancelData := context.WithCancel(context.Background())
	defer cancelData()
	relay, _ := newControlSurvivalConnectionPair()
	mux, err := datapath.New(dataCtx, 1200, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	direct, directPeer := newControlSurvivalConnectionPair()
	if err := mux.ActivateDirect(7, direct); err != nil {
		t.Fatal(err)
	}

	for sequence := uint64(1); sequence <= clockInvalidRevocationSamples; sequence++ {
		exchange, ack, received := clockFixture(2*time.Second, time.Millisecond, time.Millisecond, time.Millisecond)
		exchange.sequence, ack.Sequence = sequence, sequence
		err := runner.recordClockSample(lease, exchange, ack, received)
		if sequence < clockInvalidRevocationSamples && !errors.Is(err, errInvalidClockSample) {
			t.Fatalf("invalid sample %d returned %v", sequence, err)
		}
		if sequence == clockInvalidRevocationSamples && !errors.Is(err, errClockAuthorityRevoked) {
			t.Fatalf("revoking sample returned %v", err)
		}
	}
	select {
	case <-lease.authority.Done():
	default:
		t.Fatal("clock failure threshold retained plan authority")
	}
	if snapshot := mux.Snapshot(); snapshot.Selected != datapath.SelectedDirect || !snapshot.DirectHealthy {
		t.Fatalf("clock authority revocation closed established direct path: %#v", snapshot)
	}
	if err := mux.SendPacket([]byte("direct survives clock authority revocation")); err != nil {
		t.Fatal(err)
	}
	receiveCtx, cancelReceive := context.WithTimeout(context.Background(), time.Second)
	defer cancelReceive()
	if _, err := directPeer.ReceiveDatagram(receiveCtx); err != nil {
		t.Fatalf("direct path stopped after clock authority revocation: %v", err)
	}
}

func TestValidClockSampleResetsConsecutiveFailureCount(t *testing.T) {
	runner := controlSurvivalRunner()
	lease := runner.beginPlanSession(edgeTestRelayGeneration)
	defer runner.endPlanSession(lease)
	sequence := uint64(0)
	record := func(skew time.Duration) error {
		sequence++
		exchange, ack, received := clockFixture(skew, time.Millisecond, time.Millisecond, time.Millisecond)
		exchange.sequence, ack.Sequence = sequence, sequence
		return runner.recordClockSample(lease, exchange, ack, received)
	}
	if err := record(2 * time.Second); !errors.Is(err, errInvalidClockSample) {
		t.Fatalf("first invalid sample returned %v", err)
	}
	if err := record(0); err != nil {
		t.Fatalf("valid recovery sample returned %v", err)
	}
	for attempt := 1; attempt < clockInvalidRevocationSamples; attempt++ {
		if err := record(2 * time.Second); !errors.Is(err, errInvalidClockSample) {
			t.Fatalf("post-reset invalid sample %d returned %v", attempt, err)
		}
		select {
		case <-lease.authority.Done():
			t.Fatalf("valid sample did not reset failures before attempt %d", attempt)
		default:
		}
	}
}

func TestClockStatusContainsNoRawTimestampOrSample(t *testing.T) {
	runner := controlSurvivalRunner()
	lease := runner.beginPlanSession(edgeTestRelayGeneration)
	defer runner.endPlanSession(lease)
	exchange, ack, received := clockFixture(400*time.Millisecond, 20*time.Millisecond, 5*time.Millisecond, 20*time.Millisecond)
	if err := runner.recordClockSample(lease, exchange, ack, received); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	status := runner.state.Clock
	wire, err := json.Marshal(runner.state)
	runner.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !status.Synchronized || status.AbsoluteOffsetMillis != 400 || status.UncertaintyMillis != 20 {
		t.Fatalf("sanitized status=%#v", status)
	}
	for _, forbidden := range []string{
		"edge_wall_unix_nano", "edge_monotonic_nano", "relay_receive_unix_nano", "relay_send_unix_nano", `"host_id"`,
	} {
		if strings.Contains(string(wire), forbidden) {
			t.Fatalf("clock status exposed forbidden field %q: %s", forbidden, wire)
		}
	}
}

func TestStaleClockSamplePublishesUnsynchronized(t *testing.T) {
	runner := controlSurvivalRunner()
	runner.cfg.StatusPath = filepath.Join(t.TempDir(), "status.json")
	lease := runner.beginPlanSession(edgeTestRelayGeneration)
	defer runner.endPlanSession(lease)
	synchronizeClockForTest(runner, lease, time.Now().Add(-clockSampleMaxAge-time.Second))
	if err := runner.writeStatusNow(); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(runner.cfg.StatusPath)
	if err != nil {
		t.Fatal(err)
	}
	var status edgeState
	if err := json.Unmarshal(wire, &status); err != nil {
		t.Fatal(err)
	}
	if status.Clock.Synchronized || status.Clock.AbsoluteOffsetMillis != 0 || status.Clock.UncertaintyMillis != 0 {
		t.Fatalf("stale clock sample remained synchronized in status: %#v", status.Clock)
	}
}

func clockFixture(skew, uplink, processing, downlink time.Duration) (clockExchange, control.HeartbeatAck, time.Time) {
	base := clockTestBase()
	exchange := clockExchange{sequence: 7, edgeWall: base.UnixNano(), monotonicSample: 11, sentAt: base}
	relayReceive := base.Add(skew + uplink)
	relaySend := relayReceive.Add(processing)
	received := base.Add(uplink + processing + downlink)
	ack := control.HeartbeatAck{
		Type: "heartbeat-ack", Sequence: exchange.sequence, EdgeMonotonicNano: exchange.monotonicSample,
		RelayReceiveUnixNano: relayReceive.UnixNano(), RelaySendUnixNano: relaySend.UnixNano(),
	}
	return exchange, ack, received
}

func clockTestBase() time.Time {
	return time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
}

func validClockAckForTest(heartbeat control.Heartbeat) control.HeartbeatAck {
	return control.HeartbeatAck{
		Type: "heartbeat-ack", Sequence: heartbeat.Sequence, EdgeMonotonicNano: heartbeat.EdgeMonotonicNano,
		RelayReceiveUnixNano: heartbeat.EdgeWallUnixNano, RelaySendUnixNano: heartbeat.EdgeWallUnixNano,
	}
}

func synchronizeClockForTest(runner *Runner, lease planSessionLease, now time.Time) {
	runner.mu.Lock()
	runner.clockAuthority = clockAuthorityState{
		controlSession: lease.serial, sequence: 1, sampledAt: now, synchronized: true,
	}
	runner.state.Clock = edgeClockStatus{Synchronized: true}
	runner.mu.Unlock()
}
