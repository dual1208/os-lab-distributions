package identity

import (
	"context"
	"errors"
	"sync"
	"time"
)

const CutoffCheckInterval = 250 * time.Millisecond

var ErrCertificateCutoff = errors.New("authenticated certificate reconnect cutoff reached")

// CutoffGuard combines the ordinary elapsed-duration timer with periodic wall
// clock checks. The latter is required because a timer armed before a forward
// host-clock correction otherwise retains its original monotonic duration.
type CutoffGuard struct {
	cancel     context.CancelFunc
	done       chan struct{}
	decision   sync.Once
	cancelOnce sync.Once
}

// GuardCertificateCutoff calls expire exactly once when cutoff is reached.
// Stop releases the guard without calling expire. The callback must be bounded
// and is normally a context cancellation or authenticated connection close.
func GuardCertificateCutoff(ctx context.Context, cutoff time.Time, expire func()) (*CutoffGuard, error) {
	return guardCertificateCutoff(ctx, cutoff, expire, time.Now, CutoffCheckInterval)
}

func guardCertificateCutoff(
	ctx context.Context,
	cutoff time.Time,
	expire func(),
	now func() time.Time,
	interval time.Duration,
) (*CutoffGuard, error) {
	if ctx == nil || cutoff.IsZero() || expire == nil || now == nil || interval <= 0 {
		return nil, ErrPeerIdentity
	}
	current := now()
	if current.IsZero() || !current.Before(cutoff) {
		return nil, ErrCertificateCutoff
	}
	guardCtx, cancel := context.WithCancel(ctx)
	guard := &CutoffGuard{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(guard.done)
		deadline := time.NewTimer(cutoff.Sub(current))
		defer deadline.Stop()
		wallCheck := time.NewTicker(interval)
		defer wallCheck.Stop()
		for {
			select {
			case <-guardCtx.Done():
				return
			case <-deadline.C:
				guard.decision.Do(expire)
				return
			case <-wallCheck.C:
				if observed := now(); observed.IsZero() || !observed.Before(cutoff) {
					guard.decision.Do(expire)
					return
				}
			}
		}
	}()
	return guard, nil
}

func (g *CutoffGuard) Stop() {
	if g == nil {
		return
	}
	g.stop()
	<-g.done
}

func (g *CutoffGuard) stop() {
	g.cancelOnce.Do(func() {
		g.decision.Do(func() {})
		g.cancel()
	})
}
