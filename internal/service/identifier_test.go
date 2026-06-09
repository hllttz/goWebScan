package service

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

func TestMatchBannerSignatures(t *testing.T) {
	tests := []struct {
		name        string
		banner      string
		wantName    string
		wantProduct string
		wantVersion string
	}{
		{"vsftpd", "220 (vsFTPd 3.0.5)\r\n", "ftp", "vsftpd", "3.0.5"},
		{"postfix", "220 mx.example ESMTP Postfix\r\n", "smtp", "Postfix", ""},
		{"vnc", "RFB 003.008\n", "vnc", "RFB", "003.008"},
		{"redis", "+PONG\r\n", "redis", "Redis", ""},
		{"memcached", "VERSION 1.6.22\r\n", "memcached", "memcached", "1.6.22"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchBannerSignatures(tt.banner, goscan.ServiceResult{})
			if got.Name != tt.wantName || got.Product != tt.wantProduct || got.Version != tt.wantVersion {
				t.Fatalf("got %+v, want name=%s product=%s version=%s", got, tt.wantName, tt.wantProduct, tt.wantVersion)
			}
		})
	}
}

func TestBasicIdentifierIntensityZeroReturnsPortGuess(t *testing.T) {
	identifier := NewBasicIdentifierWithIntensity(time.Second, 512, IntensityGuess)
	got, err := identifier.Identify(context.Background(), target("127.0.0.1"), goscan.Port{Number: 22, Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "ssh" || got.Reason != "port_guess" || got.Banner != "" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestBasicIdentifierSSHBanner(t *testing.T) {
	addr, closeServer := fakeTCPServer(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_8.9\r\n"))
	})
	defer closeServer()

	got := detectAddr(t, BannerDetector{Service: "ssh", Ports: []int{22}, Parser: parseSSHBanner}, addr, 22, IntensityBanner)
	if got.Name != "ssh" || got.Product != "OpenSSH" || got.Version != "8.9" {
		t.Fatalf("unexpected ssh result: %+v", got)
	}
	if got.Extra["protocol"] != "SSH-2.0" {
		t.Fatalf("missing protocol extra: %+v", got)
	}
}

func TestBasicIdentifierHTTPServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "goscan-test/1.2.3")
		w.Header().Set("X-Powered-By", "tests")
		_, _ = w.Write([]byte("<html><title>GoScan Test</title></html>"))
	}))
	defer server.Close()

	got := detectAddr(t, HTTPDetector{}, server.Listener.Addr().String(), 80, IntensityProbe)
	if got.Name != "http" || got.Product != "goscan-test" || got.Version != "1.2.3" {
		t.Fatalf("unexpected http result: %+v", got)
	}
	if got.Extra["status"] == "" || got.Extra["server"] == "" || got.Extra["title"] != "GoScan Test" {
		t.Fatalf("missing http extras: %+v", got)
	}
}

func TestBasicIdentifierHTTPNeedsProbeIntensity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	portNumber, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := (HTTPDetector{}).Detect(context.Background(), target(host), goscan.Port{Number: uint16(portNumber), Protocol: "tcp"}, time.Second, 1024, IntensityBanner)
	if ok {
		t.Fatalf("intensity 1 should not send HTTP probe: %+v", got)
	}
}

func TestBasicIdentifierTLSServer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "tls-test/2.0")
		_, _ = w.Write([]byte("<title>TLS Test</title>"))
	}))
	defer server.Close()

	got := detectAddr(t, HTTPDetector{TLS: true}, server.Listener.Addr().String(), 443, IntensityProbe)
	if got.Name != "https" {
		t.Fatalf("got service %q, want https; result=%+v", got.Name, got)
	}
	if got.Extra["tls_handshake"] != "true" || got.Extra["tls_version"] == "" {
		t.Fatalf("missing tls extras: %+v", got)
	}
	if got.Extra["title"] != "TLS Test" {
		t.Fatalf("missing tls title: %+v", got)
	}
	if _, err := x509.ParseCertificate(server.Certificate().Raw); err != nil {
		t.Fatal(err)
	}
}

func TestBasicIdentifierRedisProbe(t *testing.T) {
	addr, closeServer := fakeTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		if strings.Contains(string(buf[:n]), "PING") {
			_, _ = conn.Write([]byte("+PONG\r\n"))
		}
	})
	defer closeServer()

	got := detectAddr(t, RedisDetector{}, addr, 6379, IntensityProbe)
	if got.Name != "redis" || got.Product != "Redis" || got.Reason != "redis_ping" {
		t.Fatalf("unexpected redis result: %+v", got)
	}
}

func TestBasicIdentifierMemcachedProbe(t *testing.T) {
	addr, closeServer := fakeTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		if strings.Contains(strings.ToLower(string(buf[:n])), "version") {
			_, _ = conn.Write([]byte("VERSION 1.6.22\r\n"))
		}
	})
	defer closeServer()

	got := detectAddr(t, MemcachedDetector{}, addr, 11211, IntensityProbe)
	if got.Name != "memcached" || got.Version != "1.6.22" || got.Reason != "memcached_version" {
		t.Fatalf("unexpected memcached result: %+v", got)
	}
}

func fakeTCPServer(t *testing.T, handle func(net.Conn)) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			handle(conn)
		}
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

func detectAddr(t *testing.T, detector ServiceDetector, addr string, detectorPort uint16, intensity int) goscan.ServiceResult {
	t.Helper()
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	portNumber, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	switch typed := detector.(type) {
	case BannerDetector:
		typed.Ports = []int{portNumber}
		detector = typed
	}
	tgt := target(host)
	tgt.Addresses = []net.IP{net.ParseIP(host)}
	port := goscan.Port{Number: detectorPort, Protocol: "tcp"}
	if portNumber > 0 {
		port.Number = uint16(portNumber)
	}
	got, ok := detector.Detect(context.Background(), tgt, port, time.Second, 1024, intensity)
	if !ok {
		t.Fatalf("detector %s did not match %s", detector.Name(), addr)
	}
	return got
}

func target(host string) goscan.Target {
	return goscan.Target{Input: host, Addresses: []net.IP{net.ParseIP(host)}}
}
