package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/hllttz/goWebScan/internal/discovery"
	"github.com/hllttz/goWebScan/internal/netutil"
	"github.com/hllttz/goWebScan/internal/osfingerprint"
	"github.com/hllttz/goWebScan/internal/report"
	"github.com/hllttz/goWebScan/internal/scanner"
	"github.com/hllttz/goWebScan/internal/service"
	"github.com/hllttz/goWebScan/internal/target"
	"github.com/hllttz/goWebScan/pkg/goscan"
)

func Run(ctx context.Context, cfg Config, out io.Writer) error {
	final, err := Scan(ctx, cfg)
	if err != nil {
		return err
	}
	if cfg.JSON {
		return report.WriteJSON(out, final)
	}
	return report.WriteText(out, final)
}

func Scan(ctx context.Context, cfg Config) (goscan.Report, error) {
	return ScanWithEvents(ctx, cfg, nil)
}

func ScanWithEvents(ctx context.Context, cfg Config, onHostResult func(goscan.HostResult)) (goscan.Report, error) {
	return ScanWithProgress(ctx, cfg, ProgressCallbacks{HostDone: onHostResult})
}

type ProgressCallbacks struct {
	Planned  func(targets int, ports int)
	HostDone func(goscan.HostResult)
	PortDone func(goscan.Target, goscan.PortResult)
}

func ScanWithProgress(ctx context.Context, cfg Config, callbacks ProgressCallbacks) (goscan.Report, error) {
	startedAt := time.Now()
	if cfg.PortWorkers <= 0 {
		return goscan.Report{}, fmt.Errorf("port-workers must be greater than zero")
	}
	if cfg.HostWorkers <= 0 {
		return goscan.Report{}, fmt.Errorf("host-workers must be greater than zero")
	}
	if cfg.Timeout <= 0 {
		return goscan.Report{}, fmt.Errorf("timeout must be greater than zero")
	}
	if err := validateScanMode(cfg.ScanMode); err != nil {
		return goscan.Report{}, err
	}

	targets, err := target.ParseTargets(ctx, cfg.Targets)
	if err != nil {
		return goscan.Report{}, err
	}
	ports, err := target.ParsePortsWithOptions(target.PortOptions{
		Expression:   cfg.Ports,
		TopPorts:     cfg.TopPorts,
		ExcludePorts: cfg.ExcludePorts,
	})
	if err != nil {
		return goscan.Report{}, err
	}
	if cfg.ScanMode == "udp" {
		for i := range ports {
			ports[i].Protocol = "udp"
		}
	}
	if callbacks.Planned != nil {
		callbacks.Planned(len(targets), len(ports))
	}

	dialer := netutil.NewDialer(cfg.Timeout)
	portScanner := newPortScanner(cfg, dialer)
	discoverer := discovery.NewTCPDiscoverer(dialer, cfg.Timeout, nil)
	identifier := service.NewBasicIdentifierWithIntensity(cfg.Timeout, cfg.BannerLimit, cfg.VersionIntensity)
	fingerprinter := osfingerprint.New(cfg.Timeout)

	results := scanHosts(ctx, targets, ports, cfg, portScanner, discoverer, identifier, fingerprinter, callbacks)

	finishedAt := time.Now()
	final := goscan.Report{
		Config:  scanConfig(cfg),
		Summary: summarizeScan(results, startedAt, finishedAt, ctx.Err() != nil),
	}
	final.SetHosts(results)
	normalizeReport(&final)
	if ctx.Err() != nil {
		return final, ctx.Err()
	}
	return final, nil
}

func normalizeReport(r *goscan.Report) {
	hosts := r.HostResults()
	sort.SliceStable(hosts, func(i, j int) bool {
		return targetSortKey(hosts[i].Target) < targetSortKey(hosts[j].Target)
	})
	for i := range hosts {
		sort.SliceStable(hosts[i].Ports, func(a, b int) bool {
			left := hosts[i].Ports[a].Port
			right := hosts[i].Ports[b].Port
			if left.Number != right.Number {
				return left.Number < right.Number
			}
			return left.Protocol < right.Protocol
		})
	}
	r.SetHosts(hosts)
	r.Summary = summarizeScan(hosts, r.Summary.StartedAt, r.Summary.FinishedAt, r.Summary.Canceled)
}

func targetSortKey(target goscan.Target) string {
	if len(target.Addresses) > 0 {
		return target.Addresses[0].String()
	}
	if target.Hostname != "" {
		return target.Hostname
	}
	return target.Input
}

func scanConfig(cfg Config) goscan.ScanConfig {
	return goscan.ScanConfig{
		Targets:          append([]string(nil), cfg.Targets...),
		Ports:            cfg.Ports,
		ScanMode:         cfg.ScanMode,
		OSFingerprint:    cfg.OSFingerprint,
		TopPorts:         cfg.TopPorts,
		ExcludePorts:     cfg.ExcludePorts,
		Discovery:        cfg.Discovery,
		ServiceVersion:   cfg.ServiceVersion,
		VersionIntensity: cfg.VersionIntensity,
		TimeoutMs:        cfg.Timeout.Milliseconds(),
		HostWorkers:      cfg.HostWorkers,
		PortWorkers:      cfg.PortWorkers,
		OpenOnly:         cfg.OpenOnly,
	}
}

func validateScanMode(mode string) error {
	switch mode {
	case "", "connect", "syn", "udp":
		return nil
	default:
		return fmt.Errorf("scan mode must be connect, syn, or udp")
	}
}

func newPortScanner(cfg Config, dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}) scanner.Scanner {
	switch cfg.ScanMode {
	case "syn":
		return scanner.NewSYNScanner(cfg.Timeout)
	case "udp":
		return scanner.NewUDPScanner(cfg.Timeout)
	default:
		return scanner.NewTCPConnectScanner(dialer, cfg.Timeout)
	}
}

func summarizeScan(hosts []goscan.HostResult, startedAt, finishedAt time.Time, canceled bool) goscan.ScanSummary {
	summary := goscan.ScanSummary{
		HostsTotal: len(hosts),
		StartedAt:  startedAt,
		FinishedAt: finishedAt,
		ElapsedMs:  finishedAt.Sub(startedAt).Milliseconds(),
		Canceled:   canceled,
	}
	for _, host := range hosts {
		switch host.Status {
		case goscan.HostUp:
			summary.HostsUp++
		case goscan.HostDown:
			summary.HostsDown++
		default:
			summary.HostsUnknown++
		}
		for _, port := range host.Ports {
			summary.PortsScanned++
			switch port.State {
			case goscan.PortOpen:
				summary.PortsOpen++
			case goscan.PortClosed:
				summary.PortsClosed++
			case goscan.PortFiltered:
				summary.PortsFiltered++
			case goscan.PortUnreachable:
				summary.PortsUnreachable++
			default:
				summary.PortsUnknown++
			}
		}
	}
	return summary
}

type scanJob struct {
	target goscan.Target
	port   goscan.Port
}

func scanHosts(ctx context.Context, targets []goscan.Target, ports []goscan.Port, cfg Config, portScanner scanner.Scanner, discoverer discovery.Discoverer, identifier service.Identifier, fingerprinter *osfingerprint.Fingerprinter, callbacks ProgressCallbacks) []goscan.HostResult {
	jobs := make(chan goscan.Target)
	results := make(chan goscan.HostResult)

	workers := cfg.HostWorkers
	if workers > len(targets) {
		workers = len(targets)
	}
	if workers < 1 {
		workers = 1
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				status := goscan.HostUp
				reason := "discovery_skipped"
				if cfg.Discovery {
					status, reason = discoverer.Discover(ctx, t)
				}
				hostResult := goscan.HostResult{Target: t, Status: status, Reason: reason}
				if status != goscan.HostDown {
					hostResult.Ports = scanTarget(ctx, t, ports, cfg.PortWorkers, portScanner, identifier, cfg.ServiceVersion && cfg.ScanMode != "udp", callbacks.PortDone)
				}
				if cfg.OSFingerprint {
					hostResult.OS = osResultPtr(fingerprinter.Fingerprint(ctx, t, hostResult.Ports))
				}
				if callbacks.HostDone != nil {
					callbacks.HostDone(hostResult)
				}
				results <- hostResult
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]goscan.HostResult, 0, len(targets))
	for result := range results {
		out = append(out, result)
	}
	return out
}

func osResultPtr(result goscan.OSResult) *goscan.OSResult {
	return &result
}

func scanTarget(ctx context.Context, t goscan.Target, ports []goscan.Port, concurrency int, connectScanner scanner.Scanner, identifier service.Identifier, identify bool, onPortDone func(goscan.Target, goscan.PortResult)) []goscan.PortResult {
	jobs := make(chan scanJob)
	results := make(chan goscan.PortResult)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				result, _ := connectScanner.Scan(ctx, job.target, job.port)
				if identify && result.State == goscan.PortOpen {
					if svc, err := identifier.Identify(ctx, job.target, job.port); err == nil {
						result.Service = &svc
					}
				}
				if onPortDone != nil {
					onPortDone(job.target, result)
				}
				results <- result
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, port := range ports {
			select {
			case jobs <- scanJob{target: t, port: port}:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]goscan.PortResult, 0, len(ports))
	for result := range results {
		out = append(out, result)
	}
	return out
}
