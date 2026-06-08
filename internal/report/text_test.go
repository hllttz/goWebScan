package report

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

func TestWriteTextNmapStyle(t *testing.T) {
	r := goscan.Report{Targets: []goscan.HostResult{{
		Target: goscan.Target{Input: "127.0.0.1", Addresses: []net.IP{net.ParseIP("127.0.0.1")}},
		Status: goscan.HostUp,
		Reason: "discovery_skipped",
		Ports: []goscan.PortResult{{
			Port:    goscan.Port{Number: 22, Protocol: "tcp"},
			State:   goscan.PortOpen,
			Reason:  "connect_succeeded",
			Service: &goscan.ServiceResult{Name: "ssh", Product: "OpenSSH", Version: "9.6"},
		}},
	}}}

	var buf bytes.Buffer
	if err := WriteText(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Starting GoScan",
		"GoScan scan report for 127.0.0.1 (127.0.0.1)",
		"PORT      STATE",
		"22/tcp",
		"OpenSSH 9.6",
		"GoScan done",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}
