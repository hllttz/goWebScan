package scanner

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

func TestUDPScannerOpenLocalPort(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		n, addr, err := conn.ReadFrom(buf)
		if err == nil && n > 0 {
			_, _ = conn.WriteTo([]byte("ok"), addr)
		}
	}()

	port := conn.LocalAddr().(*net.UDPAddr).Port
	target := goscan.Target{Input: "127.0.0.1", Addresses: []net.IP{net.ParseIP("127.0.0.1")}}
	result, err := NewUDPScanner(time.Second).Scan(context.Background(), target, goscan.Port{Number: uint16(port), Protocol: "udp"})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != goscan.PortOpen || result.Reason != "udp_response" {
		t.Fatalf("got %+v, want open udp_response", result)
	}
	<-done
}

func TestUDPProbeKnownPorts(t *testing.T) {
	for _, port := range []uint16{53, 123, 161, 9999} {
		if len(udpProbe(port)) == 0 {
			t.Fatalf("empty probe for %d", port)
		}
	}
}
