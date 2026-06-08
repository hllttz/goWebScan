package scanner

import (
	"context"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

type Scanner interface {
	Scan(ctx context.Context, target goscan.Target, port goscan.Port) (goscan.PortResult, error)
}
