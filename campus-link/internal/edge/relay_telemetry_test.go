package edge

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
)

func TestRelayTelemetryRejectsReplayRegressionAndStaleSession(t *testing.T) {
	runner := controlSurvivalRunner()
	firstLease := runner.beginPlanSession(edgeTestRelayGeneration)
	first := &control.RelayTelemetry{
		ForwardedSiteA: 10, ForwardedSiteABytes: 1000,
		ForwardedSiteB: 20, ForwardedSiteBBytes: 2000,
		Dropped: 3, DroppedBytes: 300,
	}
	if err := runner.recordRelayTelemetry(firstLease, 1, first); err != nil {
		t.Fatal(err)
	}
	for name, attempt := range map[string]struct {
		sequence  uint64
		telemetry control.RelayTelemetry
	}{
		"sequence replay":          {sequence: 1, telemetry: *first},
		"site-a packet regression": {sequence: 2, telemetry: control.RelayTelemetry{ForwardedSiteA: 9, ForwardedSiteABytes: 1000, ForwardedSiteB: 20, ForwardedSiteBBytes: 2000, Dropped: 3, DroppedBytes: 300}},
		"site-a byte regression":   {sequence: 2, telemetry: control.RelayTelemetry{ForwardedSiteA: 10, ForwardedSiteABytes: 999, ForwardedSiteB: 20, ForwardedSiteBBytes: 2000, Dropped: 3, DroppedBytes: 300}},
		"site-b packet regression": {sequence: 2, telemetry: control.RelayTelemetry{ForwardedSiteA: 10, ForwardedSiteABytes: 1000, ForwardedSiteB: 19, ForwardedSiteBBytes: 2000, Dropped: 3, DroppedBytes: 300}},
		"site-b byte regression":   {sequence: 2, telemetry: control.RelayTelemetry{ForwardedSiteA: 10, ForwardedSiteABytes: 1000, ForwardedSiteB: 20, ForwardedSiteBBytes: 1999, Dropped: 3, DroppedBytes: 300}},
		"drop packet regression":   {sequence: 2, telemetry: control.RelayTelemetry{ForwardedSiteA: 10, ForwardedSiteABytes: 1000, ForwardedSiteB: 20, ForwardedSiteBBytes: 2000, Dropped: 2, DroppedBytes: 300}},
		"drop byte regression":     {sequence: 2, telemetry: control.RelayTelemetry{ForwardedSiteA: 10, ForwardedSiteABytes: 1000, ForwardedSiteB: 20, ForwardedSiteBBytes: 2000, Dropped: 3, DroppedBytes: 299}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := runner.recordRelayTelemetry(firstLease, attempt.sequence, &attempt.telemetry); !errors.Is(err, errInvalidRelayTelemetry) {
				t.Fatalf("regressing telemetry returned %v", err)
			}
		})
	}

	runner.endPlanSession(firstLease)
	if err := runner.recordRelayTelemetry(firstLease, 2, first); !errors.Is(err, errInvalidRelayTelemetry) {
		t.Fatalf("revoked session telemetry returned %v", err)
	}
	runner.mu.Lock()
	if runner.state.RelayTelemetry != nil {
		runner.mu.Unlock()
		t.Fatal("control loss did not clear relay telemetry")
	}
	runner.mu.Unlock()

	secondLease := runner.beginPlanSession(edgeTestRelayGeneration)
	defer runner.endPlanSession(secondLease)
	if err := runner.recordRelayTelemetry(firstLease, 2, first); !errors.Is(err, errInvalidRelayTelemetry) {
		t.Fatalf("old lease updated replacement session: %v", err)
	}
	reset := &control.RelayTelemetry{ForwardedSiteA: 1, ForwardedSiteABytes: 10, ForwardedSiteB: 2, ForwardedSiteBBytes: 20}
	if err := runner.recordRelayTelemetry(secondLease, 1, reset); err != nil {
		t.Fatalf("replacement session could not establish its own baseline: %v", err)
	}
}

func TestRelayTelemetryConcurrentUpdatesRemainMonotonic(t *testing.T) {
	runner := controlSurvivalRunner()
	lease := runner.beginPlanSession(edgeTestRelayGeneration)
	defer runner.endPlanSession(lease)

	const updates = 256
	start := make(chan struct{})
	var joined sync.WaitGroup
	for sequence := uint64(1); sequence <= updates; sequence++ {
		sequence := sequence
		joined.Add(1)
		go func() {
			defer joined.Done()
			<-start
			telemetry := &control.RelayTelemetry{
				ForwardedSiteA:      sequence,
				ForwardedSiteABytes: sequence * 100,
				ForwardedSiteB:      sequence * 2,
				ForwardedSiteBBytes: sequence * 200,
				Dropped:             sequence / 3,
				DroppedBytes:        (sequence / 3) * 300,
			}
			_ = runner.recordRelayTelemetry(lease, sequence, telemetry)
		}()
	}
	close(start)
	joined.Wait()

	runner.mu.Lock()
	status := runner.state.RelayTelemetry
	runner.mu.Unlock()
	if status == nil || status.Sequence != updates || status.ForwardedPackets.SiteA != updates ||
		status.ForwardedBytes.SiteA != updates*100 || status.ForwardedPackets.SiteB != updates*2 ||
		status.ForwardedBytes.SiteB != updates*200 || status.DroppedPackets != updates/3 ||
		status.DroppedBytes != (updates/3)*300 {
		t.Fatalf("concurrent telemetry did not converge on the maximum coherent snapshot: %#v", status)
	}
}

func TestAuthenticatedHeartbeatRequiresAndRecordsRelayTelemetry(t *testing.T) {
	for _, test := range []struct {
		name      string
		telemetry *control.RelayTelemetry
		wantError bool
	}{
		{name: "missing", wantError: true},
		{name: "present", telemetry: &control.RelayTelemetry{
			ForwardedSiteA: 7, ForwardedSiteABytes: 700,
			ForwardedSiteB: 9, ForwardedSiteBBytes: 900,
			Dropped: 2, DroppedBytes: 200,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			runner := controlSurvivalRunner()
			lease := runner.beginPlanSession(edgeTestRelayGeneration)
			defer runner.endPlanSession(lease)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			errCh := make(chan error, 1)
			go runner.heartbeatPlanSessionWithIntervalUntil(
				ctx, cancel, client, json.NewEncoder(client), control.NewDecoder(client), errCh, lease, time.Millisecond, time.Time{},
			)
			serverDone := make(chan error, 1)
			go func() {
				var heartbeat control.Heartbeat
				if err := control.NewDecoder(server).Decode(&heartbeat); err != nil {
					serverDone <- err
					return
				}
				ack := validClockAckForTest(heartbeat)
				ack.Telemetry = test.telemetry
				time.Sleep(time.Millisecond)
				serverDone <- json.NewEncoder(server).Encode(ack)
			}()
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
			if test.wantError {
				select {
				case err := <-errCh:
					if !errors.Is(err, errInvalidRelayTelemetry) {
						t.Fatalf("missing telemetry returned %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("missing telemetry did not fail the authenticated control session")
				}
				return
			}
			deadline := time.Now().Add(time.Second)
			for {
				runner.mu.Lock()
				status := runner.state.RelayTelemetry
				runner.mu.Unlock()
				if status != nil {
					if status.Sequence != 1 || status.ForwardedPackets.SiteA != 7 || status.ForwardedBytes.SiteA != 700 ||
						status.ForwardedPackets.SiteB != 9 || status.ForwardedBytes.SiteB != 900 ||
						status.DroppedPackets != 2 || status.DroppedBytes != 200 {
						t.Fatalf("authenticated telemetry status mismatch: %#v", status)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("authenticated telemetry was not recorded")
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestRelayTelemetryStatusExposesOnlySanitizedSessionSerial(t *testing.T) {
	runner := controlSurvivalRunner()
	lease := runner.beginPlanSession(edgeTestRelayGeneration)
	defer runner.endPlanSession(lease)
	telemetry := &control.RelayTelemetry{
		ForwardedSiteA: 4, ForwardedSiteABytes: 400,
		ForwardedSiteB: 5, ForwardedSiteBBytes: 500,
		Dropped: 1, DroppedBytes: 100,
	}
	if err := runner.recordRelayTelemetry(lease, 1, telemetry); err != nil {
		t.Fatal(err)
	}
	runner.mu.Lock()
	wire, err := json.Marshal(runner.state)
	runner.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	relay, ok := decoded["relay_telemetry"].(map[string]any)
	if !ok {
		t.Fatalf("relay telemetry missing from status: %s", wire)
	}
	if _, leaked := relay["session"]; leaked {
		t.Fatalf("status exposed a secret-derived session value: %s", wire)
	}
	if got := relay["control_session"]; got != float64(lease.serial) || lease.serial == 0 {
		t.Fatalf("status control session=%v want=%d", got, lease.serial)
	}
	for key := range relay {
		switch key {
		case "control_session", "sequence", "forwarded_packets", "forwarded_bytes", "dropped_packets", "dropped_bytes":
		default:
			t.Fatalf("unexpected relay telemetry status field %q", key)
		}
	}
	for _, field := range []string{"forwarded_packets", "forwarded_bytes"} {
		counters, ok := relay[field].(map[string]any)
		if !ok || len(counters) != 2 || counters["site-a"] == nil || counters["site-b"] == nil {
			t.Fatalf("status %s schema is not the exact two directions: %s", field, wire)
		}
	}
	if relay["dropped_bytes"] != float64(100) {
		t.Fatalf("status dropped byte accounting mismatch: %s", wire)
	}
}

func TestPlanSessionSerialExhaustionIsPermanentAndFailClosed(t *testing.T) {
	runner := controlSurvivalRunner()
	oldLease := runner.beginPlanSession(edgeTestRelayGeneration)
	runner.mu.Lock()
	runner.planSessionSerial = ^uint64(0)
	runner.mu.Unlock()
	if lease := runner.beginPlanSession(edgeTestRelayGeneration); lease.valid() {
		t.Fatal("plan authority wrapped after session serial exhaustion")
	}
	select {
	case <-oldLease.authority.Done():
	default:
		t.Fatal("serial exhaustion did not synchronously revoke prior authority")
	}
	if lease := runner.beginPlanSession(edgeTestRelayGeneration); lease.valid() {
		t.Fatal("session serial exhaustion was not permanent")
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.activePlanSession != 0 || runner.relayGeneration != "" || runner.planSessionSerial != ^uint64(0) {
		t.Fatalf("serial exhaustion left authority active: serial=%d active=%d", runner.planSessionSerial, runner.activePlanSession)
	}
}

func TestPlanAttemptContextIsCanceledBeforeRevocationReturns(t *testing.T) {
	runner := controlSurvivalRunner()
	lease := runner.beginPlanSession(edgeTestRelayGeneration)
	attemptCtx, cancelAttempt := planAttemptContext(context.Background(), lease, time.Now().Add(time.Hour))
	defer cancelAttempt()
	runner.endPlanSession(lease)
	select {
	case <-attemptCtx.Done():
	default:
		t.Fatal("plan attempt remained live after endPlanSession returned")
	}
}
