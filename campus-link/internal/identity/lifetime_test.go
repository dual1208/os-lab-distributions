package identity

import (
	"errors"
	"testing"
	"time"
)

func TestSessionDeadlineUsesEarliestCertificateAndRotationMargin(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	first := Verified{NotAfter: now.Add(2 * time.Hour)}
	second := Verified{NotAfter: now.Add(time.Hour)}
	deadline, err := SessionDeadline(now, first, second)
	if err != nil {
		t.Fatal(err)
	}
	if want := second.NotAfter.Add(-ReconnectMargin); !deadline.Equal(want) {
		t.Fatalf("deadline=%s want=%s", deadline, want)
	}
	if _, err := SessionDeadline(now, Verified{NotAfter: now.Add(ReconnectMargin)}); err == nil {
		t.Fatal("certificate inside the reconnect margin was accepted")
	} else if !errors.Is(err, ErrReconnectMargin) {
		t.Fatalf("unexpected reconnect-margin error: %v", err)
	}
	if _, err := SessionDeadline(time.Time{}, first); err == nil {
		t.Fatal("zero current time accepted")
	}
	if _, err := SessionDeadline(now, Verified{}); err == nil {
		t.Fatal("zero certificate expiry accepted")
	}
	justOutside := Verified{NotAfter: now.Add(ReconnectMargin + time.Nanosecond)}
	if deadline, err := SessionDeadline(now, justOutside); err != nil || !deadline.Equal(now.Add(time.Nanosecond)) {
		t.Fatalf("certificate outside margin rejected: deadline=%s err=%v", deadline, err)
	}
}

func TestBoundedDeadlineNeverExceedsCutoff(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cutoff := now.Add(3 * time.Second)
	if deadline, err := BoundedDeadline(now, time.Second, cutoff); err != nil || !deadline.Equal(now.Add(time.Second)) {
		t.Fatalf("short deadline changed: deadline=%s err=%v", deadline, err)
	}
	if deadline, err := BoundedDeadline(now, 5*time.Second, cutoff); err != nil || !deadline.Equal(cutoff) {
		t.Fatalf("deadline was not capped: deadline=%s err=%v", deadline, err)
	}
	for name, test := range map[string]struct {
		now     time.Time
		timeout time.Duration
		cutoff  time.Time
	}{
		"zero now":       {timeout: time.Second, cutoff: cutoff},
		"zero timeout":   {now: now, cutoff: cutoff},
		"zero cutoff":    {now: now, timeout: time.Second},
		"elapsed cutoff": {now: now, timeout: time.Second, cutoff: now},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := BoundedDeadline(test.now, test.timeout, test.cutoff); err == nil {
				t.Fatal("unsafe deadline accepted")
			}
		})
	}
}

func TestPinSlotNameIsSanitized(t *testing.T) {
	if PinSlotName(0) != "current" || PinSlotName(1) != "next" || PinSlotName(2) != "invalid" {
		t.Fatal("unexpected pin-slot labels")
	}
}
