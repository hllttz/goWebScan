package report

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

func TestWriteTextGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "text.golden", buf.String())
}

func TestWriteJSONGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "json.golden", buf.String())
}

func TestWriteCSVGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "csv.golden", buf.String())
}

func TestWriteCSVHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, goscan.Report{}); err != nil {
		t.Fatal(err)
	}
	want := "host,ip,port,protocol,state,reason,service,product,version,banner,rtt_ms\n"
	if got := buf.String(); got != want {
		t.Fatalf("csv = %q, want %q", got, want)
	}
}

func sampleReport() goscan.Report {
	started := time.Date(2026, 6, 9, 10, 0, 0, 0, time.UTC)
	finished := started.Add(1230 * time.Millisecond)
	hosts := []goscan.HostResult{{
		Target: goscan.Target{Input: "127.0.0.1", Addresses: []net.IP{net.ParseIP("127.0.0.1")}},
		Status: goscan.HostUp,
		Reason: "-Pn",
		Ports: []goscan.PortResult{
			{
				Port:    goscan.Port{Number: 22, Protocol: "tcp"},
				State:   goscan.PortOpen,
				Reason:  "connected",
				Latency: 12 * time.Millisecond,
				Service: &goscan.ServiceResult{Name: "ssh", Product: "OpenSSH", Version: "8.9", Banner: "SSH-2.0-OpenSSH_8.9\r\n", Reason: "ssh_banner"},
			},
			{
				Port:    goscan.Port{Number: 80, Protocol: "tcp"},
				State:   goscan.PortClosed,
				Reason:  "connection_refused",
				Latency: 3 * time.Millisecond,
				Service: &goscan.ServiceResult{Name: "http"},
			},
			{
				Port:    goscan.Port{Number: 443, Protocol: "tcp"},
				State:   goscan.PortFiltered,
				Reason:  "timeout",
				Latency: time.Second,
				Service: &goscan.ServiceResult{Name: "https", Extra: map[string]string{"tls_cn": "example.test", "tls_version": "TLS1.3"}},
			},
		},
	}}
	report := goscan.Report{
		Config: goscan.ScanConfig{
			Targets:          []string{"127.0.0.1"},
			Ports:            "22,80,443",
			Discovery:        false,
			ServiceVersion:   true,
			VersionIntensity: 2,
			TimeoutMs:        2000,
			HostWorkers:      10,
			PortWorkers:      100,
		},
		Summary: goscan.ScanSummary{
			HostsTotal:    1,
			HostsUp:       1,
			PortsScanned:  3,
			PortsOpen:     1,
			PortsClosed:   1,
			PortsFiltered: 1,
			StartedAt:     started,
			FinishedAt:    finished,
			ElapsedMs:     1230,
		},
	}
	report.SetHosts(hosts)
	return report
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("%s mismatch\n--- got ---\n%s\n--- want ---\n%s", name, got, string(want))
	}
}
