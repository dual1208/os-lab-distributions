//go:build !linux

package rendezvous

type platformBootAnchorSource struct{}

func (platformBootAnchorSource) BootAnchorDigest() ([32]byte, error) {
	return [32]byte{}, ErrBootAnchor
}
