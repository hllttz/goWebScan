//go:build linux || darwin || freebsd || netbsd || openbsd

package osfingerprint

import "syscall"

func readTTL(fd uintptr) (int, error) {
	ttl, err := syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL)
	if err == nil {
		return ttl, nil
	}
	return 0, err
}
