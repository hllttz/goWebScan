package service

import (
	"context"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

type UnknownDetector struct{}

func (UnknownDetector) Name() string { return "unknown" }

func (UnknownDetector) MatchPort(_ int) bool { return false }

func (UnknownDetector) Detect(ctx context.Context, target goscan.Target, port goscan.Port, timeout time.Duration, bannerLimit int, intensity int) (goscan.ServiceResult, bool) {
	if intensity < IntensityBanner {
		return goscan.ServiceResult{Name: "unknown", Confidence: 0, Reason: "unknown"}, true
	}
	conn, err := dial(ctx, target, port, timeout, false)
	if err != nil {
		return goscan.ServiceResult{}, false
	}
	defer conn.Close()
	banner := readBanner(conn, timeout, bannerLimit)
	result := goscan.ServiceResult{Name: "unknown", Confidence: 0, Reason: "unknown"}
	if banner != "" {
		result.Banner = banner
		result.Reason = "banner"
		result.Confidence = 20
		result = matchBannerSignatures(banner, result)
	}
	return result, true
}
