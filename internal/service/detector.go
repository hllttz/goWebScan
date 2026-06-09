package service

import (
	"context"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

const (
	IntensityGuess  = 0
	IntensityBanner = 1
	IntensityProbe  = 2
)

type Identifier interface {
	Identify(ctx context.Context, target goscan.Target, port goscan.Port) (goscan.ServiceResult, error)
}

type ServiceDetector interface {
	Name() string
	MatchPort(port int) bool
	Detect(ctx context.Context, target goscan.Target, port goscan.Port, timeout time.Duration, bannerLimit int, intensity int) (goscan.ServiceResult, bool)
}

type BasicIdentifier struct {
	registry    *Registry
	timeout     time.Duration
	bannerLimit int
	intensity   int
}

func NewBasicIdentifier(timeout time.Duration, bannerLimit int) *BasicIdentifier {
	return NewBasicIdentifierWithIntensity(timeout, bannerLimit, IntensityBanner)
}

func NewBasicIdentifierWithIntensity(timeout time.Duration, bannerLimit int, intensity int) *BasicIdentifier {
	if bannerLimit <= 0 {
		bannerLimit = 512
	}
	if intensity < IntensityGuess {
		intensity = IntensityGuess
	}
	if intensity > IntensityProbe {
		intensity = IntensityProbe
	}
	return &BasicIdentifier{
		registry:    NewDefaultRegistry(),
		timeout:     timeout,
		bannerLimit: bannerLimit,
		intensity:   intensity,
	}
}

func (i *BasicIdentifier) Identify(ctx context.Context, target goscan.Target, port goscan.Port) (goscan.ServiceResult, error) {
	return i.registry.Detect(ctx, target, port, i.timeout, i.bannerLimit, i.intensity), nil
}
