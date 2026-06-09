package service

import (
	"context"
	"strings"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

type RedisDetector struct{}

func (RedisDetector) Name() string { return "redis" }

func (RedisDetector) MatchPort(port int) bool { return port == 6379 }

func (RedisDetector) Detect(ctx context.Context, target goscan.Target, port goscan.Port, timeout time.Duration, bannerLimit int, intensity int) (goscan.ServiceResult, bool) {
	if intensity < IntensityProbe {
		return goscan.ServiceResult{Name: "redis", Confidence: 40, Reason: "port_guess"}, true
	}
	conn, err := dial(ctx, target, port, timeout, false)
	if err != nil {
		return goscan.ServiceResult{}, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
	banner := readBanner(conn, timeout, bannerLimit)
	if banner == "" {
		return goscan.ServiceResult{Name: "redis", Confidence: 40, Reason: "port_open_no_banner"}, true
	}
	result := matchBannerSignatures(banner, goscan.ServiceResult{Name: "redis", Product: "Redis", Confidence: 80, Banner: banner, Reason: "redis_ping"})
	if strings.Contains(strings.ToUpper(banner), "PONG") || strings.Contains(strings.ToUpper(banner), "NOAUTH") {
		result.Name = "redis"
		result.Product = "Redis"
		result.Confidence = 95
		result.Reason = "redis_ping"
	}
	return result, true
}
