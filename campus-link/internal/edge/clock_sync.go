package edge

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/dual1208/os-lab-distributions/campus-link/internal/control"
)

const (
	maxClockOffset                = time.Second
	maxClockSampleRTT             = 5 * time.Second
	maxRelayClockProcessing       = time.Second
	maxWallMonotonicDivergence    = 50 * time.Millisecond
	clockSampleMaxAge             = 15 * time.Second
	clockInvalidRevocationSamples = 3
)

var (
	errInvalidClockSample    = errors.New("invalid authenticated clock sample")
	errClockAuthorityRevoked = errors.New("clock sample failures revoked plan authority")
	processMonotonicOrigin   = time.Now()
	lastMonotonicSample      atomic.Uint64
)

type clockExchange struct {
	sequence        uint64
	edgeWall        int64
	monotonicSample uint64
	sentAt          time.Time
}

type clockMeasurement struct {
	absoluteOffset time.Duration
	uncertainty    time.Duration
}

type clockAuthorityState struct {
	controlSession     uint64
	sequence           uint64
	sampledAt          time.Time
	consecutiveInvalid uint8
	synchronized       bool
}

func newClockExchange(sequence uint64, sentAt time.Time) (clockExchange, error) {
	if sequence == 0 || sentAt.IsZero() || !control.ValidClockUnixNano(sentAt.UnixNano()) {
		return clockExchange{}, errInvalidClockSample
	}
	sample, err := nextMonotonicSample(sentAt)
	if err != nil {
		return clockExchange{}, err
	}
	return clockExchange{
		sequence: sequence, edgeWall: sentAt.UnixNano(), monotonicSample: sample, sentAt: sentAt,
	}, nil
}

func nextMonotonicSample(now time.Time) (uint64, error) {
	elapsed := now.Sub(processMonotonicOrigin)
	if elapsed < 0 || uint64(elapsed) >= control.MaxMonotonicSample {
		return 0, errInvalidClockSample
	}
	candidate := uint64(elapsed) + 1
	for {
		prior := lastMonotonicSample.Load()
		if candidate <= prior {
			if prior == control.MaxMonotonicSample {
				return 0, errInvalidClockSample
			}
			candidate = prior + 1
		}
		if lastMonotonicSample.CompareAndSwap(prior, candidate) {
			return candidate, nil
		}
	}
}

func (exchange clockExchange) heartbeat() control.Heartbeat {
	return control.Heartbeat{
		Type: "heartbeat", Sequence: exchange.sequence, EdgeWallUnixNano: exchange.edgeWall,
		EdgeMonotonicNano: exchange.monotonicSample,
	}
}

func evaluateClockExchange(exchange clockExchange, ack control.HeartbeatAck, receivedAt time.Time) (clockMeasurement, error) {
	return evaluateClockExchangeCaptured(exchange, ack, receivedAt, receivedAt.UnixNano())
}

func evaluateClockExchangeCaptured(
	exchange clockExchange,
	ack control.HeartbeatAck,
	receivedAt time.Time,
	receivedWallUnixNano int64,
) (clockMeasurement, error) {
	if exchange.sequence == 0 || ack.Type != "heartbeat-ack" || ack.Sequence != exchange.sequence ||
		!control.ValidClockUnixNano(exchange.edgeWall) || !control.ValidMonotonicSample(exchange.monotonicSample) ||
		ack.EdgeMonotonicNano != exchange.monotonicSample || !control.ValidMonotonicSample(ack.EdgeMonotonicNano) ||
		exchange.sentAt.IsZero() || exchange.sentAt.UnixNano() != exchange.edgeWall || receivedAt.IsZero() ||
		!control.ValidClockUnixNano(receivedWallUnixNano) ||
		!control.ValidClockUnixNano(ack.RelayReceiveUnixNano) || !control.ValidClockUnixNano(ack.RelaySendUnixNano) {
		return clockMeasurement{}, fmt.Errorf("%w: noncanonical fields", errInvalidClockSample)
	}

	monotonicRTT := receivedAt.Sub(exchange.sentAt)
	if monotonicRTT <= 0 || monotonicRTT > maxClockSampleRTT {
		return clockMeasurement{}, fmt.Errorf("%w: round-trip bound", errInvalidClockSample)
	}
	wallRTT := receivedWallUnixNano - exchange.edgeWall
	if wallRTT < 0 || absoluteNanoseconds(wallRTT-monotonicRTT.Nanoseconds()) > int64(maxWallMonotonicDivergence) {
		return clockMeasurement{}, fmt.Errorf("%w: local wall correlation", errInvalidClockSample)
	}
	relayProcessing := ack.RelaySendUnixNano - ack.RelayReceiveUnixNano
	if relayProcessing < 0 || relayProcessing > int64(maxRelayClockProcessing) ||
		monotonicRTT.Nanoseconds() <= relayProcessing {
		return clockMeasurement{}, fmt.Errorf("%w: relay processing bound", errInvalidClockSample)
	}

	// Derive t3 from t0 plus the local monotonic RTT. The separately captured
	// receive wall sample above is used only to detect a wall-clock step.
	edgeReceive := exchange.edgeWall + monotonicRTT.Nanoseconds()
	if !control.ValidClockUnixNano(edgeReceive) {
		return clockMeasurement{}, fmt.Errorf("%w: derived receive time", errInvalidClockSample)
	}
	lower := ack.RelaySendUnixNano - edgeReceive
	upper := ack.RelayReceiveUnixNano - exchange.edgeWall
	if lower > upper || lower < -int64(maxClockOffset) || upper > int64(maxClockOffset) {
		return clockMeasurement{}, fmt.Errorf("%w: offset interval", errInvalidClockSample)
	}

	// Once both interval endpoints are within one second, these additions and
	// subtractions cannot overflow. Round both public magnitudes upward so the
	// sanitized millisecond evidence never understates uncertainty.
	absMidpointNanos := absoluteNanoseconds(lower + upper)
	absMidpointNanos = (absMidpointNanos + 1) / 2
	uncertaintyNanos := (upper - lower + 1) / 2
	measurement := clockMeasurement{
		absoluteOffset: time.Duration(absMidpointNanos),
		uncertainty:    time.Duration(uncertaintyNanos),
	}
	if ceilMilliseconds(measurement.absoluteOffset)+ceilMilliseconds(measurement.uncertainty) > 1000 {
		return clockMeasurement{}, fmt.Errorf("%w: rounded offset interval", errInvalidClockSample)
	}
	return measurement, nil
}

func absoluteNanoseconds(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}

func ceilMilliseconds(value time.Duration) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64((value + time.Millisecond - 1) / time.Millisecond)
}

func (r *Runner) recordClockSample(
	lease planSessionLease,
	exchange clockExchange,
	ack control.HeartbeatAck,
	receivedAt time.Time,
) error {
	measurement, sampleErr := evaluateClockExchange(exchange, ack, receivedAt)
	if r == nil || !lease.valid() {
		return fmt.Errorf("%w: plan lease unavailable", errInvalidClockSample)
	}
	r.mu.Lock()
	if !r.planSessionCurrentLocked(lease) {
		r.mu.Unlock()
		return fmt.Errorf("%w: plan lease stale", errInvalidClockSample)
	}
	if sampleErr == nil {
		r.clockAuthority = clockAuthorityState{
			controlSession: lease.serial, sequence: exchange.sequence, sampledAt: receivedAt, synchronized: true,
		}
		r.state.Clock = edgeClockStatus{
			Synchronized:         true,
			AbsoluteOffsetMillis: ceilMilliseconds(measurement.absoluteOffset),
			UncertaintyMillis:    ceilMilliseconds(measurement.uncertainty),
		}
		r.mu.Unlock()
		r.writeStatus()
		return nil
	}

	failures := r.clockAuthority.consecutiveInvalid
	if failures < clockInvalidRevocationSamples {
		failures++
	}
	r.clockAuthority = clockAuthorityState{
		controlSession: lease.serial, consecutiveInvalid: failures,
	}
	r.state.Clock = edgeClockStatus{}
	revoke := failures >= clockInvalidRevocationSamples
	r.mu.Unlock()
	r.writeStatus()
	if revoke {
		r.endPlanSession(lease)
		return errClockAuthorityRevoked
	}
	return sampleErr
}

func (r *Runner) clockSynchronizedLocked(lease planSessionLease, now time.Time) bool {
	state := r.clockAuthority
	if !state.synchronized || state.controlSession != lease.serial {
		return false
	}
	return clockAuthorityFresh(state, now)
}

func (r *Runner) clockStatusCurrentLocked(now time.Time) bool {
	state := r.clockAuthority
	return r.activePlanSession != 0 && state.controlSession == r.activePlanSession && clockAuthorityFresh(state, now)
}

func clockAuthorityFresh(state clockAuthorityState, now time.Time) bool {
	if !state.synchronized || state.sequence == 0 || state.sampledAt.IsZero() || now.IsZero() {
		return false
	}
	age := now.Sub(state.sampledAt)
	return age >= 0 && age <= clockSampleMaxAge
}

func (r *Runner) resetClockAuthorityLocked() {
	r.clockAuthority = clockAuthorityState{}
	r.state.Clock = edgeClockStatus{}
}
