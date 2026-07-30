//go:build unix

package rendezvous

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func validateEpochOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return ErrEpochState
	}
	return nil
}

func validateEpochDirectorySecurity(info os.FileInfo) error {
	if info.Mode().Perm()&0022 != 0 {
		return ErrEpochState
	}
	return validateEpochOwner(info)
}

func validateEpochStateSecurity(info os.FileInfo) error {
	if info.Mode().Perm() != 0600 {
		return ErrEpochState
	}
	return validateEpochOwner(info)
}

func syncEpochDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

func lockEpochState(path string) (func(), error) {
	fd, err := unix.Open(path+".lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path+".lock")
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrEpochState
	}
	info, err := file.Stat()
	if err != nil || validateEpochStateSecurity(info) != nil {
		_ = file.Close()
		return nil, ErrEpochState
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	return func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = file.Close()
	}, nil
}
