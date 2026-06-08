package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"goscan/internal/app"
	"goscan/internal/report"
	"goscan/pkg/goscan"
)

func Execute(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		printUsage(stdout)
		return 0
	}
	switch args[0] {
	case "scan":
		return executeScan(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func executeScan(args []string, stdout, stderr io.Writer) int {
	cfg := app.DefaultConfig()
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.Ports, "p", cfg.Ports, "ports to scan, for example 22,80,443 or 1-1024")
	fs.StringVar(&cfg.Ports, "ports", cfg.Ports, "ports to scan, for example 22,80,443 or 1-1024")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "per-connection timeout")
	fs.IntVar(&cfg.PortWorkers, "port-workers", cfg.PortWorkers, "maximum concurrent port scan jobs per host")
	fs.IntVar(&cfg.HostWorkers, "host-workers", cfg.HostWorkers, "maximum concurrent target hosts")
	fs.IntVar(&cfg.PortWorkers, "concurrency", cfg.PortWorkers, "deprecated alias for --port-workers")
	fs.IntVar(&cfg.HostConcurrency, "host-concurrency", cfg.HostConcurrency, "reserved for per-host concurrency")
	fs.BoolVar(&cfg.JSON, "json", cfg.JSON, "write JSON output")
	fs.BoolVar(&cfg.ServiceVersion, "sV", cfg.ServiceVersion, "enable active service version detection")
	fs.BoolVar(&cfg.ServiceVersion, "service", cfg.ServiceVersion, "deprecated alias for -sV")
	fs.IntVar(&cfg.BannerLimit, "banner-limit", cfg.BannerLimit, "maximum banner bytes to keep")
	noDiscovery := fs.Bool("no-discovery", false, "skip host discovery")
	pn := fs.Bool("Pn", false, "skip host discovery")
	flagArgs, targets := splitScanArgs(args)
	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}
	cfg.Discovery = !*noDiscovery && !*pn
	cfg.Targets = append(fs.Args(), targets...)
	if len(cfg.Targets) == 0 {
		fmt.Fprintln(stderr, "scan requires at least one target")
		return 2
	}
	if cfg.Timeout < time.Millisecond {
		fmt.Fprintln(stderr, "timeout is too small")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	result, err := runScanWithCLIProgress(ctx, cfg, stderr)
	if cfg.JSON {
		_ = report.WriteJSON(stdout, result)
	} else {
		_ = report.WriteText(stdout, result)
	}
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, "Scan canceled. Partial results were written.")
		return 130
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func runScanWithCLIProgress(ctx context.Context, cfg app.Config, stderr io.Writer) (goscan.Report, error) {
	start := time.Now()
	var total int64
	var done int64
	var lastProgress int64
	var mu sync.Mutex
	var hostsDone int

	progress := app.ProgressCallbacks{
		Planned: func(targets int, ports int) {
			total = int64(targets * ports)
			fmt.Fprintf(stderr, "Starting GoScan: %d target(s), %d port(s), %d total probe(s)\n", targets, ports, total)
		},
		PortDone: func(_ goscan.Target, _ goscan.PortResult) {
			current := atomic.AddInt64(&done, 1)
			if total == 0 {
				return
			}
			percent := current * 100 / total
			last := atomic.LoadInt64(&lastProgress)
			if current == total || percent >= last+10 {
				if atomic.CompareAndSwapInt64(&lastProgress, last, percent) {
					fmt.Fprintf(stderr, "Progress: %d/%d probes complete (%d%%)\n", current, total, percent)
				}
			}
		},
		HostDone: func(host goscan.HostResult) {
			mu.Lock()
			hostsDone++
			currentHosts := hostsDone
			mu.Unlock()
			fmt.Fprintf(stderr, "Host complete: %s status=%s ports=%d (%d done)\n", host.Target.Input, host.Status, len(host.Ports), currentHosts)
		},
	}

	result, err := app.ScanWithProgress(ctx, cfg, progress)
	fmt.Fprintf(stderr, "Elapsed: %s\n", time.Since(start).Round(time.Millisecond))
	return result, err
}

func splitScanArgs(args []string) ([]string, []string) {
	valueFlags := map[string]struct{}{
		"-p": {}, "--p": {}, "-ports": {}, "--ports": {},
		"-timeout": {}, "--timeout": {},
		"-concurrency": {}, "--concurrency": {},
		"-port-workers": {}, "--port-workers": {},
		"-host-workers": {}, "--host-workers": {},
		"-host-concurrency": {}, "--host-concurrency": {},
		"-banner-limit": {}, "--banner-limit": {},
	}

	var flagArgs []string
	var targets []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			targets = append(targets, args[i+1:]...)
			break
		}
		if len(arg) > 0 && arg[0] == '-' {
			flagArgs = append(flagArgs, arg)
			name := arg
			if idx := strings.IndexByte(arg, '='); idx >= 0 {
				name = arg[:idx]
			}
			if _, ok := valueFlags[name]; ok && !strings.Contains(arg, "=") && i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}
		targets = append(targets, arg)
	}
	return flagArgs, targets
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  goscan scan <target...> -p 22,80,443")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  goscan scan 127.0.0.1 -Pn -p 22,80,443")
	fmt.Fprintln(w, "  goscan scan 192.168.1.0/24 -p 1-1024 --timeout 2s --host-workers 20 --port-workers 200 -sV")
}
