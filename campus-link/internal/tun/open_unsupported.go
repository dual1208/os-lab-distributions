//go:build !linux

package tun

import (
	"errors"
	"os"
)

// Open keeps configuration, TLS, binding, and state-machine tests portable.
// Real TUN creation remains Linux-only and fails closed on other platforms.
func Open(string) (*os.File, error) {
	return nil, errors.New("TUN devices are supported only on Linux")
}
