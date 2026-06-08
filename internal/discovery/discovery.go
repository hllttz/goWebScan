package discovery

import (
	"context"

	"goscan/pkg/goscan"
)

type Discoverer interface {
	Discover(ctx context.Context, target goscan.Target) (goscan.HostStatus, string)
}
