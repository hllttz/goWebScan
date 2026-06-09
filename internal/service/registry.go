package service

import (
	"context"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

type Registry struct {
	detectors []ServiceDetector
}

func NewDefaultRegistry() *Registry {
	return &Registry{detectors: []ServiceDetector{
		HTTPDetector{TLS: false},
		HTTPDetector{TLS: true},
		BannerDetector{Service: "ssh", Ports: []int{22}, Parser: parseSSHBanner},
		BannerDetector{Service: "ftp", Ports: []int{21}, Parser: matchBannerSignatures},
		BannerDetector{Service: "smtp", Ports: []int{25}, Parser: matchBannerSignatures},
		BannerDetector{Service: "pop3", Ports: []int{110}, Parser: matchBannerSignatures},
		BannerDetector{Service: "imap", Ports: []int{143}, Parser: matchBannerSignatures},
		BannerDetector{Service: "mysql", Ports: []int{3306}, Parser: matchBannerSignatures},
		BannerDetector{Service: "vnc", Ports: []int{5900}, Parser: matchBannerSignatures},
		RedisDetector{},
		MemcachedDetector{},
		PostgresDetector{},
		UnknownDetector{},
	}}
}

func (r *Registry) Detect(ctx context.Context, target goscan.Target, port goscan.Port, timeout time.Duration, bannerLimit int, intensity int) goscan.ServiceResult {
	result := portGuess(port.Number)
	if intensity == IntensityGuess {
		return result
	}
	for _, detector := range r.detectors {
		if !detector.MatchPort(int(port.Number)) {
			continue
		}
		if detected, ok := detector.Detect(ctx, target, port, timeout, bannerLimit, intensity); ok {
			return mergeService(result, detected)
		}
	}
	for _, detector := range r.detectors {
		if detector.MatchPort(int(port.Number)) {
			continue
		}
		if detected, ok := detector.Detect(ctx, target, port, timeout, bannerLimit, intensity); ok {
			return mergeService(result, detected)
		}
	}
	return result
}

func mergeService(base, detected goscan.ServiceResult) goscan.ServiceResult {
	if detected.Name == "" {
		detected.Name = base.Name
	}
	if detected.Product == "" {
		detected.Product = base.Product
	}
	if detected.Version == "" {
		detected.Version = base.Version
	}
	if detected.Confidence == 0 {
		detected.Confidence = base.Confidence
	}
	if detected.Reason == "" {
		detected.Reason = base.Reason
	}
	if detected.Extra == nil {
		detected.Extra = base.Extra
	}
	return detected
}
