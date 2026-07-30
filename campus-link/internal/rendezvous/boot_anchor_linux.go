//go:build linux

package rendezvous

import (
	"io"
	"os"
)

const linuxBootIDPath = "/proc/sys/kernel/random/boot_id"

type platformBootAnchorSource struct{}

func (platformBootAnchorSource) BootAnchorDigest() ([32]byte, error) {
	return readLinuxBootAnchor(linuxBootIDPath)
}

func readLinuxBootAnchor(path string) ([32]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return [32]byte{}, ErrBootAnchor
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, 65))
	if err != nil || len(value) > 64 {
		return [32]byte{}, ErrBootAnchor
	}
	return hashCanonicalLinuxBootID(value)
}
