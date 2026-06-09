package service

import (
	"context"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

type PostgresDetector struct{}

func (PostgresDetector) Name() string { return "postgresql" }

func (PostgresDetector) MatchPort(port int) bool { return port == 5432 }

func (PostgresDetector) Detect(_ context.Context, _ goscan.Target, _ goscan.Port, _ time.Duration, _ int, _ int) (goscan.ServiceResult, bool) {
	return goscan.ServiceResult{Name: "postgresql", Product: "PostgreSQL", Confidence: 40, Reason: "port_guess"}, true
}
