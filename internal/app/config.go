package app

import "time"

type Config struct {
	Targets         []string
	Ports           string
	Timeout         time.Duration
	PortWorkers     int
	HostWorkers     int
	HostConcurrency int
	Discovery       bool
	ServiceVersion  bool
	JSON            bool
	BannerLimit     int
}

func DefaultConfig() Config {
	return Config{
		Ports:           "top",
		Timeout:         2 * time.Second,
		PortWorkers:     100,
		HostWorkers:     10,
		HostConcurrency: 0,
		Discovery:       true,
		ServiceVersion:  false,
		BannerLimit:     1024,
	}
}
