package identity

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCutoffGuardDetectsForwardWallClockStep(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	observed := base
	now := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return observed
	}
	expired := make(chan struct{}, 1)
	guard, err := guardCertificateCutoff(
		context.Background(), base.Add(time.Hour), func() { expired <- struct{}{} },
		now, time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Stop()
	mu.Lock()
	observed = base.Add(2 * time.Hour)
	mu.Unlock()
	select {
	case <-expired:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("forward wall-clock step did not expire authority")
	}
}

func TestCutoffGuardStopIsIdempotentAndSuppressesExpiry(t *testing.T) {
	var expired atomic.Uint64
	guard, err := guardCertificateCutoff(
		context.Background(), time.Now().Add(time.Hour), func() { expired.Add(1) },
		time.Now, time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	guard.Stop()
	guard.Stop()
	if expired.Load() != 0 {
		t.Fatal("stopped cutoff guard invoked expiry callback")
	}
}

func TestCutoffGuardStopWinsBeforeQueuedExpiry(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	wallChecks := make(chan struct{}, 1)
	releaseCheck := make(chan struct{})
	var calls atomic.Uint64
	now := func() time.Time {
		if calls.Add(1) == 1 {
			return base
		}
		wallChecks <- struct{}{}
		<-releaseCheck
		return base.Add(2 * time.Hour)
	}
	var expired atomic.Uint64
	guard, err := guardCertificateCutoff(
		context.Background(), base.Add(time.Hour), func() { expired.Add(1) },
		now, time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	<-wallChecks
	guard.stop()
	close(releaseCheck)
	guard.Stop()
	if expired.Load() != 0 {
		t.Fatal("expiry callback ran after stop had claimed the guard")
	}
}

func TestCutoffGuardRejectsElapsedAndInvalidInputs(t *testing.T) {
	now := time.Now()
	if _, err := GuardCertificateCutoff(context.Background(), now, func() {}); !errors.Is(err, ErrCertificateCutoff) {
		t.Fatalf("elapsed cutoff returned %v", err)
	}
	for name, test := range map[string]struct {
		ctx      context.Context
		cutoff   time.Time
		expire   func()
		interval time.Duration
	}{
		"nil context":   {cutoff: now.Add(time.Hour), expire: func() {}, interval: time.Second},
		"zero cutoff":   {ctx: context.Background(), expire: func() {}, interval: time.Second},
		"nil callback":  {ctx: context.Background(), cutoff: now.Add(time.Hour), interval: time.Second},
		"zero interval": {ctx: context.Background(), cutoff: now.Add(time.Hour), expire: func() {}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := guardCertificateCutoff(test.ctx, test.cutoff, test.expire, time.Now, test.interval); err == nil {
				t.Fatal("invalid cutoff guard inputs accepted")
			}
		})
	}
}
