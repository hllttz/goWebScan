package scanner

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

func TestTCPConnectScannerOpenLocalPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	target := goscan.Target{Input: "127.0.0.1", Addresses: []net.IP{net.ParseIP("127.0.0.1")}}
	scanner := NewTCPConnectScanner(&net.Dialer{Timeout: time.Second}, time.Second)
	result, err := scanner.Scan(context.Background(), target, goscan.Port{Number: uint16(port), Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != goscan.PortOpen {
		t.Fatalf("got %s, want %s", result.State, goscan.PortOpen)
	}
	<-done
}

func TestTCPConnectScannerClosedLocalPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	target := goscan.Target{Input: "127.0.0.1", Addresses: []net.IP{net.ParseIP("127.0.0.1")}}
	scanner := NewTCPConnectScanner(&net.Dialer{Timeout: time.Second}, time.Second)
	result, err := scanner.Scan(context.Background(), target, goscan.Port{Number: uint16(port), Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != goscan.PortClosed {
		t.Fatalf("got %s, want %s; error=%s", result.State, goscan.PortClosed, result.Error)
	}
}
