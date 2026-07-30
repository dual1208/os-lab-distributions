package edge

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"time"
)

// controlRetryDelay returns an overflow-safe exponential backoff. Production
// callers add bounded jitter after computing this deterministic ceiling; the
// pure helper keeps the cap independently testable.
func controlRetryDelay(attempt uint, initial, maximum time.Duration) time.Duration {
	if initial <= 0 || maximum < initial {
		return 0
	}
	delay := initial
	for remaining := attempt; remaining > 0 && delay < maximum; remaining-- {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

// jitterRetryDelay spreads reconnects over the final quarter of the bounded
// delay without ever exceeding that delay. Entropy failure conservatively
// uses the full delay.
func jitterRetryDelay(delay time.Duration, random io.Reader) time.Duration {
	if delay <= 1 {
		return delay
	}
	if random == nil {
		random = rand.Reader
	}
	floor := delay - delay/4
	span := delay - floor
	var sample [8]byte
	if _, err := io.ReadFull(random, sample[:]); err != nil {
		return delay
	}
	return floor + time.Duration(binary.BigEndian.Uint64(sample[:])%uint64(span+1))
}
