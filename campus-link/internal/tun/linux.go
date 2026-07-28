//go:build linux

package tun

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type ifreq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	_     [40 - unix.IFNAMSIZ - 2]byte
}

func Open(name string) (*os.File, error) {
	if name == "" || len(name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("invalid TUN name %q", name)
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ifr := ifreq{Flags: unix.IFF_TUN | unix.IFF_NO_PI}
	copy(ifr.Name[:], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		_ = unix.Close(fd)
		return nil, errno
	}
	return os.NewFile(uintptr(fd), "/dev/net/tun:"+name), nil
}
