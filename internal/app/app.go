package app

import (
	"context"
	"fmt"
	"io"
	"sync"

	"goscan/internal/discovery"
	"goscan/internal/netutil"
	"goscan/internal/report"
	"goscan/internal/scanner"
	"goscan/internal/service"
	"goscan/internal/target"
	"goscan/pkg/goscan"
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
	if cfg.PortWorkers <= 0 {
		return goscan.Report{}, fmt.Errorf("port-workers must be greater than zero")
	}
	if cfg.HostWorkers <= 0 {
		return goscan.Report{}, fmt.Errorf("host-workers must be greater than zero")
	}
	if cfg.Timeout <= 0 {
		return goscan.Report{}, fmt.Errorf("timeout must be greater than zero")
	}

	targets, err := target.ParseTargets(ctx, cfg.Targets)
	if err != nil {
		return goscan.Report{}, err
	}
	ports, err := target.ParsePorts(cfg.Ports)
	if err != nil {
		return goscan.Report{}, err
	}
	if callbacks.Planned != nil {
		callbacks.Planned(len(targets), len(ports))
	}

	dialer := netutil.NewDialer(cfg.Timeout)
	connectScanner := scanner.NewTCPConnectScanner(dialer, cfg.Timeout)
	discoverer := discovery.NewTCPDiscoverer(dialer, cfg.Timeout, nil)
	identifier := service.NewBasicIdentifier(cfg.Timeout, cfg.BannerLimit)

	results := scanHosts(ctx, targets, ports, cfg, connectScanner, discoverer, identifier, callbacks)

	final := goscan.Report{Targets: results}
	if ctx.Err() != nil {
		return final, ctx.Err()
	}
	return final, nil
}

type scanJob struct {
	target goscan.Target
	port   goscan.Port
}

func scanHosts(ctx context.Context, targets []goscan.Target, ports []goscan.Port, cfg Config, connectScanner scanner.Scanner, discoverer discovery.Discoverer, identifier service.Identifier, callbacks ProgressCallbacks) []goscan.HostResult {
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
					hostResult.Ports = scanTarget(ctx, t, ports, cfg.PortWorkers, connectScanner, identifier, cfg.ServiceVersion, callbacks.PortDone)
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
