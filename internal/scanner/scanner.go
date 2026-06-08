package scanner

import (
	"context"

	"goscan/pkg/goscan"
)

type Scanner interface {
	Scan(ctx context.Context, target goscan.Target, port goscan.Port) (goscan.PortResult, error)
}
