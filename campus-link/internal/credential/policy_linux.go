//go:build linux

package credential

import (
	"errors"
	"os"
	"syscall"
)

func validatePlatformPolicy(info os.FileInfo, leaf bool, kind Kind) error {
	mode := info.Mode().Perm()
	if mode&0022 != 0 {
		return errors.New("credential path component is group- or world-writable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("credential path component is not root-owned")
	}
	if !leaf {
		return nil
	}
	switch kind {
	case PublicCertificate:
		if mode&0400 == 0 || mode&0111 != 0 {
			return errors.New("public credential must be owner-readable and non-executable")
		}
	case EdgePrivateKey, RelayPrivateKey:
		if mode != 0600 && mode != 0640 {
			return errors.New("private key mode must be 0600 or 0640")
		}
		if mode == 0640 && stat.Gid != uint32(os.Getegid()) {
			return errors.New("0640 private key group must match the process effective group")
		}
	default:
		return errors.New("unknown credential policy")
	}
	return nil
}
