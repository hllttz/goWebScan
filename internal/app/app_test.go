package app

import (
	"context"
	"net"
	"testing"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

type fakeScanner struct{}

func (fakeScanner) Scan(_ context.Context, _ goscan.Target, port goscan.Port) (goscan.PortResult, error) {
	return goscan.PortResult{Port: port, State: goscan.PortClosed, Reason: "test"}, nil
}

type fakeDiscoverer struct{}

func (fakeDiscoverer) Discover(_ context.Context, _ goscan.Target) (goscan.HostStatus, string) {
	return goscan.HostUp, "test"
}

type fakeIdentifier struct{}

func (fakeIdentifier) Identify(_ context.Context, _ goscan.Target, _ goscan.Port) (goscan.ServiceResult, error) {
	return goscan.ServiceResult{}, nil
}

func TestScanHostsReturnsDeterministicOrder(t *testing.T) {
	targets := []goscan.Target{
		{Input: "b", Addresses: []net.IP{net.ParseIP("127.0.0.2")}},
		{Input: "a", Addresses: []net.IP{net.ParseIP("127.0.0.1")}},
	}
	ports := []goscan.Port{
		{Number: 443, Protocol: "tcp"},
		{Number: 22, Protocol: "tcp"},
	}

	results := scanHosts(context.Background(), targets, ports, Config{
		Discovery:   true,
		HostWorkers: 2,
		PortWorkers: 2,
	}, fakeScanner{}, fakeDiscoverer{}, fakeIdentifier{}, ProgressCallbacks{})

	report := goscan.Report{Targets: results}
	normalizeReport(&report)

	if got := report.Targets[0].Target.Addresses[0].String(); got != "127.0.0.1" {
		t.Fatalf("first target = %s, want 127.0.0.1", got)
	}
	if got := report.Targets[1].Target.Addresses[0].String(); got != "127.0.0.2" {
		t.Fatalf("second target = %s, want 127.0.0.2", got)
	}
	if got := report.Targets[0].Ports[0].Port.Number; got != 22 {
		t.Fatalf("first port = %d, want 22", got)
	}
	if got := report.Targets[0].Ports[1].Port.Number; got != 443 {
		t.Fatalf("second port = %d, want 443", got)
	}
}
