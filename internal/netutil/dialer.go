package netutil

import (
	"context"
	"net"
	"time"
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func NewDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout}
}
