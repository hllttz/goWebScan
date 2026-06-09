//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd

package osfingerprint

import "fmt"

func readTTL(_ uintptr) (int, error) {
	return 0, fmt.Errorf("TTL sampling is not supported on this platform")
}
