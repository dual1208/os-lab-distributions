package rendezvous

import (
	"bytes"
	"crypto/sha256"
	"errors"
)

var ErrBootAnchor = errors.New("rendezvous boot anchor unavailable or invalid")

// BootAnchorSource returns only a sanitized digest. Implementations must never
// expose the host's raw boot identifier to persisted state, logs, or status.
type BootAnchorSource interface {
	BootAnchorDigest() ([sha256.Size]byte, error)
}

// BootAnchorSourceFunc adapts a function for deterministic tests and platform
// integrations. Production uses the Linux source selected by build tags.
type BootAnchorSourceFunc func() ([sha256.Size]byte, error)

func (f BootAnchorSourceFunc) BootAnchorDigest() ([sha256.Size]byte, error) {
	if f == nil {
		return [sha256.Size]byte{}, ErrBootAnchor
	}
	return f()
}

func readBootAnchor(source BootAnchorSource) ([sha256.Size]byte, error) {
	if source == nil {
		return [sha256.Size]byte{}, ErrBootAnchor
	}
	digest, err := source.BootAnchorDigest()
	if err != nil || digest == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{}, ErrBootAnchor
	}
	return digest, nil
}

// hashCanonicalLinuxBootID validates Linux's canonical UUID form before
// hashing it. At most one final LF is accepted; whitespace and uppercase forms
// are rejected so the stored digest has one unambiguous source representation.
func hashCanonicalLinuxBootID(value []byte) ([sha256.Size]byte, error) {
	if len(value) == 37 && value[36] == '\n' {
		value = value[:36]
	}
	if len(value) != 36 || bytes.Equal(value, []byte("00000000-0000-0000-0000-000000000000")) {
		return [sha256.Size]byte{}, ErrBootAnchor
	}
	for index, b := range value {
		switch index {
		case 8, 13, 18, 23:
			if b != '-' {
				return [sha256.Size]byte{}, ErrBootAnchor
			}
		default:
			if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
				return [sha256.Size]byte{}, ErrBootAnchor
			}
		}
	}
	return sha256.Sum256(value), nil
}
