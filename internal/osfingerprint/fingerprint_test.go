package osfingerprint

import (
	"testing"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

func TestInferFromTTL(t *testing.T) {
	tests := []struct {
		ttl    int
		family string
	}{
		{64, "unix"},
		{128, "windows"},
		{255, "network"},
	}
	for _, tt := range tests {
		got := inferFromTTL(tt.ttl)
		if got.Family != tt.family {
			t.Fatalf("ttl %d family = %q, want %q", tt.ttl, got.Family, tt.family)
		}
	}
}

func TestRefineFromPorts(t *testing.T) {
	result := goscan.OSResult{}
	refineFromPorts(&result, []goscan.PortResult{{
		Port:  goscan.Port{Number: 445, Protocol: "tcp"},
		State: goscan.PortOpen,
	}})
	if result.Family != "windows" || result.Confidence < 60 {
		t.Fatalf("unexpected result: %+v", result)
	}
}
