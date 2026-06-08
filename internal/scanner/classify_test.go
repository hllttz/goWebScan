package scanner

import (
	"context"
	"errors"
	"syscall"
	"testing"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

func TestClassifyDialError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantState  goscan.PortState
		wantReason string
	}{
		{"open", nil, goscan.PortOpen, "connect_succeeded"},
		{"refused", syscall.ECONNREFUSED, goscan.PortClosed, "connection_refused"},
		{"timeout", context.DeadlineExceeded, goscan.PortFiltered, "timeout"},
		{"unreachable", syscall.EHOSTUNREACH, goscan.PortUnreachable, "network_unreachable"},
		{"permission", errors.New("socket: operation not permitted"), goscan.PortUnknown, "permission_denied"},
		{"unknown", errors.New("boom"), goscan.PortUnknown, "unclassified_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotState, gotReason := ClassifyDialError(tt.err)
			if gotState != tt.wantState || gotReason != tt.wantReason {
				t.Fatalf("got (%s,%s), want (%s,%s)", gotState, gotReason, tt.wantState, tt.wantReason)
			}
		})
	}
}
