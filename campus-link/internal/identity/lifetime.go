package identity

import (
	"errors"
	"time"
)

const ReconnectMargin = 5 * time.Minute

var ErrReconnectMargin = errors.New("authenticated certificate is inside the reconnect margin")

// SessionDeadline returns the earliest authenticated leaf cutoff minus the
// rotation margin. Callers close and reconnect at this deadline so a TLS/QUIC
// session cannot outlive its certificate.
func SessionDeadline(now time.Time, verified ...Verified) (time.Time, error) {
	if now.IsZero() || len(verified) == 0 {
		return time.Time{}, ErrPeerIdentity
	}
	earliest := verified[0].NotAfter
	if earliest.IsZero() {
		return time.Time{}, ErrPeerIdentity
	}
	for _, candidate := range verified[1:] {
		if candidate.NotAfter.IsZero() {
			return time.Time{}, ErrPeerIdentity
		}
		if candidate.NotAfter.Before(earliest) {
			earliest = candidate.NotAfter
		}
	}
	deadline := earliest.Add(-ReconnectMargin)
	if !deadline.After(now) {
		return time.Time{}, ErrReconnectMargin
	}
	return deadline, nil
}

// BoundedDeadline returns a positive I/O deadline that never exceeds the
// authenticated session cutoff.
func BoundedDeadline(now time.Time, timeout time.Duration, cutoff time.Time) (time.Time, error) {
	if now.IsZero() || timeout <= 0 || cutoff.IsZero() || !cutoff.After(now) {
		return time.Time{}, ErrReconnectMargin
	}
	deadline := now.Add(timeout)
	if deadline.After(cutoff) {
		deadline = cutoff
	}
	return deadline, nil
}

func PinSlotName(slot int) string {
	switch slot {
	case 0:
		return "current"
	case 1:
		return "next"
	default:
		return "invalid"
	}
}
