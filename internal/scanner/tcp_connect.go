package scanner

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

type TCPConnectScanner struct {
	dialer interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	}
	timeout time.Duration
}

func NewTCPConnectScanner(dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}, timeout time.Duration) *TCPConnectScanner {
	return &TCPConnectScanner{dialer: dialer, timeout: timeout}
}

func (s *TCPConnectScanner) Scan(ctx context.Context, target goscan.Target, port goscan.Port) (goscan.PortResult, error) {
	start := time.Now()
	address := net.JoinHostPort(firstAddress(target), strconv.Itoa(int(port.Number)))

	scanCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	conn, err := s.dialer.DialContext(scanCtx, "tcp", address)
	latency := time.Since(start)
	if err == nil {
		_ = conn.Close()
		return goscan.PortResult{Port: port, State: goscan.PortOpen, Reason: "connect_succeeded", Latency: latency}, nil
	}

	state, reason := ClassifyDialError(err)
	result := goscan.PortResult{Port: port, State: state, Reason: reason, Latency: latency, Error: err.Error()}
	return result, nil
}

func ClassifyDialError(err error) (goscan.PortState, string) {
	if err == nil {
		return goscan.PortOpen, "connect_succeeded"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return goscan.PortFiltered, "timeout"
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return goscan.PortFiltered, "timeout"
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return goscan.PortClosed, "connection_refused"
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return goscan.PortUnreachable, "network_unreachable"
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection refused"):
		return goscan.PortClosed, "connection_refused"
	case strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "timed out"):
		return goscan.PortFiltered, "timeout"
	case strings.Contains(msg, "no route to host"),
		strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "host is unreachable"):
		return goscan.PortUnreachable, "network_unreachable"
	case strings.Contains(msg, "operation not permitted"),
		strings.Contains(msg, "permission denied"):
		return goscan.PortUnknown, "permission_denied"
	default:
		return goscan.PortUnknown, "unclassified_error"
	}
}

func firstAddress(target goscan.Target) string {
	if len(target.Addresses) > 0 {
		return target.Addresses[0].String()
	}
	return target.Hostname
}
