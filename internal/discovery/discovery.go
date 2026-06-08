package discovery

import (
	"context"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

type Discoverer interface {
	Discover(ctx context.Context, target goscan.Target) (goscan.HostStatus, string)
}
