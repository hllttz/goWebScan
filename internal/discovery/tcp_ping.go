package discovery

import (
	"context"
	"net"
	"strconv"
	"time"

	"goscan/internal/scanner"
	"goscan/pkg/goscan"
)

type TCPDiscoverer struct {
	dialer interface {
		DialContext(ctx context.Context, network, address string) (net.Conn, error)
	}
	timeout time.Duration
	ports   []uint16
}

func NewTCPDiscoverer(dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}, timeout time.Duration, ports []uint16) *TCPDiscoverer {
	if len(ports) == 0 {
		ports = []uint16{80, 443, 22, 3389, 445}
	}
	return &TCPDiscoverer{dialer: dialer, timeout: timeout, ports: ports}
}

func (d *TCPDiscoverer) Discover(ctx context.Context, target goscan.Target) (goscan.HostStatus, string) {
	host := discoveryAddress(target)
	if host == "" {
		return goscan.HostUnknown, "no_address"
	}

	sawTimeout := false
	sawUnreachable := false
	for _, port := range d.ports {
		probeCtx, cancel := context.WithTimeout(ctx, d.timeout)
		conn, err := d.dialer.DialContext(probeCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		cancel()
		if err == nil {
			_ = conn.Close()
			return goscan.HostUp, "tcp_probe_connect_succeeded"
		}
		state, _ := scanner.ClassifyDialError(err)
		if state == goscan.PortClosed {
			return goscan.HostUp, "tcp_probe_connection_refused"
		}
		if state == goscan.PortFiltered || state == goscan.PortUnknown {
			sawTimeout = true
		}
		if state == goscan.PortUnreachable {
			sawUnreachable = true
		}
	}
	if sawUnreachable && !sawTimeout {
		return goscan.HostDown, "network_unreachable"
	}
	if sawTimeout {
		return goscan.HostUnknown, "tcp_probes_inconclusive"
	}
	return goscan.HostDown, "tcp_probes_failed"
}

func discoveryAddress(target goscan.Target) string {
	if len(target.Addresses) > 0 {
		return target.Addresses[0].String()
	}
	return target.Hostname
}
