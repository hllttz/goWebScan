package osfingerprint

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

type Fingerprinter struct {
	timeout time.Duration
}

func New(timeout time.Duration) *Fingerprinter {
	return &Fingerprinter{timeout: timeout}
}

func (f *Fingerprinter) Fingerprint(ctx context.Context, target goscan.Target, ports []goscan.PortResult) goscan.OSResult {
	if len(target.Addresses) == 0 {
		return goscan.OSResult{Reason: "no_ip_address", Confidence: 0}
	}
	ttl, ttlOK := f.sampleTTL(ctx, target)
	os := inferFromTTL(ttl)
	if ttlOK {
		os.Reason = "ttl_heuristic"
		os.Extra = map[string]string{"observed_ttl": strconv.Itoa(ttl)}
	}
	refineFromPorts(&os, ports)
	if os.Name == "" {
		os.Name = "unknown"
		os.Family = "unknown"
		os.Reason = "insufficient_fingerprint_data"
	}
	return os
}

func (f *Fingerprinter) sampleTTL(ctx context.Context, target goscan.Target) (int, bool) {
	host := target.Addresses[0].String()
	dialer := net.Dialer{Timeout: f.timeout}
	dialCtx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	conn, err := dialer.DialContext(dialCtx, "udp", net.JoinHostPort(host, "33434"))
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	raw, ok := conn.(interface {
		SyscallConn() (syscallConn, error)
	})
	if !ok {
		return 0, false
	}
	sys, err := raw.SyscallConn()
	if err != nil {
		return 0, false
	}
	var ttl int
	var ttlErr error
	if err := sys.Control(func(fd uintptr) {
		ttl, ttlErr = readTTL(fd)
	}); err != nil || ttlErr != nil {
		return 0, false
	}
	return ttl, ttl > 0
}

type syscallConn interface {
	Control(func(fd uintptr)) error
	Read(func(fd uintptr) bool) error
	Write(func(fd uintptr) bool) error
}

func inferFromTTL(ttl int) goscan.OSResult {
	switch {
	case ttl <= 0:
		return goscan.OSResult{}
	case ttl <= 64:
		return goscan.OSResult{Name: "Linux/Unix", Family: "unix", Confidence: 45}
	case ttl <= 128:
		return goscan.OSResult{Name: "Windows", Family: "windows", Confidence: 45}
	default:
		return goscan.OSResult{Name: "Network device", Family: "network", Confidence: 35}
	}
}

func refineFromPorts(result *goscan.OSResult, ports []goscan.PortResult) {
	if result.Extra == nil {
		result.Extra = make(map[string]string)
	}
	for _, port := range ports {
		if port.State != goscan.PortOpen {
			continue
		}
		switch port.Port.Number {
		case 3389, 445, 135:
			if result.Family == "" || result.Family == "windows" {
				result.Name = "Windows"
				result.Family = "windows"
				result.Confidence = max(result.Confidence, 60)
				result.Extra["port_hint"] = fmt.Sprintf("%d/tcp", port.Port.Number)
			}
		case 22:
			if result.Family == "" || result.Family == "unix" {
				result.Name = "Linux/Unix"
				result.Family = "unix"
				result.Confidence = max(result.Confidence, 55)
				result.Extra["port_hint"] = "22/tcp"
			}
		}
	}
	if result.Reason == "" && result.Extra["port_hint"] != "" {
		result.Reason = "open_port_heuristic"
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
