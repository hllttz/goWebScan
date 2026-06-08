package service

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"goscan/pkg/goscan"
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

func TestBasicIdentifierHTTPServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "goscan-test/1.2.3")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	portNumber, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	identifier := NewBasicIdentifier(time.Second, 1024)
	got, err := identifier.Identify(context.Background(),
		goscan.Target{Input: "127.0.0.1", Addresses: []net.IP{net.ParseIP("127.0.0.1")}},
		goscan.Port{Number: uint16(portNumber), Protocol: "tcp"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "http" {
		t.Fatalf("got service %q, want http; result=%+v", got.Name, got)
	}
	if got.Banner == "" {
		t.Fatalf("expected captured HTTP banner: %+v", got)
	}
}
