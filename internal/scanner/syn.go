package scanner

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

type SYNScanner struct {
	timeout time.Duration
}

func NewSYNScanner(timeout time.Duration) *SYNScanner {
	return &SYNScanner{timeout: timeout}
}

func (s *SYNScanner) Scan(ctx context.Context, target goscan.Target, port goscan.Port) (goscan.PortResult, error) {
	start := time.Now()
	result := goscan.PortResult{Port: port}
	if err := checkRawSocketPermission(firstAddress(target)); err != nil {
		result.State = goscan.PortUnknown
		result.Reason = "raw_socket_unavailable"
		result.Error = err.Error()
		result.Latency = time.Since(start)
		return result, nil
	}

	// Go's standard library does not expose a portable half-open SYN scanner.
	// After confirming raw socket capability, fall back to a TCP connect probe
	// and mark the reason so users know this is not a true packet-level result.
	connect := NewTCPConnectScanner(&net.Dialer{Timeout: s.timeout}, s.timeout)
	result, err := connect.Scan(ctx, target, port)
	result.Reason = "syn_mode_connect_fallback_" + result.Reason
	return result, err
}

func checkRawSocketPermission(address string) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("SYN scan requires raw packet support and is not implemented for windows")
	}
	ip := net.ParseIP(address)
	network := "ip4:tcp"
	bind := "0.0.0.0"
	if ip != nil && ip.To4() == nil {
		network = "ip6:tcp"
		bind = "::"
	}
	conn, err := net.ListenPacket(network, bind)
	if err != nil {
		return fmt.Errorf("SYN scan requires raw socket privileges: %w", err)
	}
	_ = conn.Close()
	return nil
}
