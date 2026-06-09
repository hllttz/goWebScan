package service

import (
	"context"
	"time"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

type BannerDetector struct {
	Service string
	Ports   []int
	Parser  resultParser
}

func (d BannerDetector) Name() string {
	return d.Service
}

func (d BannerDetector) MatchPort(port int) bool {
	for _, candidate := range d.Ports {
		if candidate == port {
			return true
		}
	}
	return false
}

func (d BannerDetector) Detect(ctx context.Context, target goscan.Target, port goscan.Port, timeout time.Duration, bannerLimit int, intensity int) (goscan.ServiceResult, bool) {
	if intensity < IntensityBanner {
		return goscan.ServiceResult{}, false
	}
	if !d.MatchPort(int(port.Number)) {
		return goscan.ServiceResult{}, false
	}
	conn, err := dial(ctx, target, port, timeout, false)
	if err != nil {
		return goscan.ServiceResult{}, false
	}
	defer conn.Close()

	banner := readBanner(conn, timeout, bannerLimit)
	if banner == "" {
		return goscan.ServiceResult{Name: d.Service, Confidence: 40, Reason: "port_open_no_banner"}, d.Service != ""
	}

	result := goscan.ServiceResult{
		Name:       d.Service,
		Banner:     banner,
		Confidence: 60,
		Reason:     "banner",
	}
	if d.Parser != nil {
		result = d.Parser(banner, result)
	}
	return result, true
}
