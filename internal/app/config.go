package app

import "time"

type Config struct {
	Targets          []string
	Ports            string
	ScanMode         string
	OSFingerprint    bool
	TopPorts         int
	ExcludePorts     string
	Timeout          time.Duration
	PortWorkers      int
	HostWorkers      int
	HostConcurrency  int
	Discovery        bool
	ServiceVersion   bool
	VersionIntensity int
	JSON             bool
	OpenOnly         bool
	OutputText       string
	OutputJSON       string
	OutputCSV        string
	Silent           bool
	Verbose          bool
	NoColor          bool
	BannerLimit      int
}

func DefaultConfig() Config {
	return Config{
		Ports:            "top",
		ScanMode:         "connect",
		Timeout:          2 * time.Second,
		PortWorkers:      100,
		HostWorkers:      10,
		HostConcurrency:  0,
		Discovery:        true,
		ServiceVersion:   false,
		VersionIntensity: 1,
		BannerLimit:      1024,
	}
}
