package service

import (
	"context"
	"strings"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

type MemcachedDetector struct{}

func (MemcachedDetector) Name() string { return "memcached" }

func (MemcachedDetector) MatchPort(port int) bool { return port == 11211 }

func (MemcachedDetector) Detect(ctx context.Context, target goscan.Target, port goscan.Port, timeout time.Duration, bannerLimit int, intensity int) (goscan.ServiceResult, bool) {
	if intensity < IntensityProbe {
		return goscan.ServiceResult{Name: "memcached", Confidence: 40, Reason: "port_guess"}, true
	}
	conn, err := dial(ctx, target, port, timeout, false)
	if err != nil {
		return goscan.ServiceResult{}, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte("version\r\n"))
	banner := readBanner(conn, timeout, bannerLimit)
	if banner == "" {
		return goscan.ServiceResult{Name: "memcached", Confidence: 40, Reason: "port_open_no_banner"}, true
	}
	result := matchBannerSignatures(banner, goscan.ServiceResult{Name: "memcached", Product: "memcached", Confidence: 80, Banner: banner, Reason: "memcached_version"})
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(banner)), "VERSION ") {
		result.Name = "memcached"
		result.Product = "memcached"
		result.Reason = "memcached_version"
		result.Confidence = 95
	}
	return result, true
}
