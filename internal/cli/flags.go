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

	"github.com/hllttz/goWebScan/internal/app"
	"github.com/hllttz/goWebScan/internal/report"
	"github.com/hllttz/goWebScan/pkg/goscan"
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
	fs.IntVar(&cfg.TopPorts, "top-ports", cfg.TopPorts, "scan the N most common TCP ports")
	fs.IntVar(&cfg.PortWorkers, "concurrency", cfg.PortWorkers, "deprecated alias for --port-workers")
	fs.IntVar(&cfg.HostConcurrency, "host-concurrency", cfg.HostConcurrency, "reserved for per-host concurrency")
	fs.BoolVar(&cfg.JSON, "json", cfg.JSON, "write JSON output")
	fs.BoolVar(&cfg.OpenOnly, "open", cfg.OpenOnly, "show only open ports in output")
	fs.BoolVar(&cfg.ServiceVersion, "sV", cfg.ServiceVersion, "enable active service version detection")
	fs.BoolVar(&cfg.ServiceVersion, "service", cfg.ServiceVersion, "deprecated alias for -sV")
	fs.IntVar(&cfg.BannerLimit, "banner-limit", cfg.BannerLimit, "maximum banner bytes to keep")
	fs.StringVar(&cfg.ExcludePorts, "exclude-ports", cfg.ExcludePorts, "ports to exclude, for example 25,137-139")
	fs.StringVar(&cfg.OutputText, "oT", cfg.OutputText, "write normal text output to file")
	fs.StringVar(&cfg.OutputJSON, "oJ", cfg.OutputJSON, "write JSON output to file")
	fs.StringVar(&cfg.OutputCSV, "oC", cfg.OutputCSV, "write CSV output to file")
	fs.BoolVar(&cfg.Silent, "silent", cfg.Silent, "suppress progress output")
	fs.BoolVar(&cfg.Verbose, "verbose", cfg.Verbose, "write verbose progress output")
	fs.BoolVar(&cfg.NoColor, "no-color", cfg.NoColor, "disable colored output")
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
	if cfg.OpenOnly {
		result = filterOpen(result)
	}
	if writeErr := writeOutputs(stdout, result, cfg); writeErr != nil {
		fmt.Fprintln(stderr, writeErr)
		return 1
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
			if cfg.Silent {
				return
			}
			fmt.Fprintf(stderr, "Starting GoScan: %d target(s), %d port(s), %d total probe(s)\n", targets, ports, total)
		},
		PortDone: func(_ goscan.Target, _ goscan.PortResult) {
			if cfg.Silent {
				return
			}
			current := atomic.AddInt64(&done, 1)
			if total == 0 {
				return
			}
			percent := current * 100 / total
			last := atomic.LoadInt64(&lastProgress)
			step := int64(10)
			if cfg.Verbose {
				step = 1
			}
			if current == total || percent >= last+step {
				if atomic.CompareAndSwapInt64(&lastProgress, last, percent) {
					fmt.Fprintf(stderr, "Progress: %d/%d probes complete (%d%%)\n", current, total, percent)
				}
			}
		},
		HostDone: func(host goscan.HostResult) {
			if cfg.Silent {
				return
			}
			mu.Lock()
			hostsDone++
			currentHosts := hostsDone
			mu.Unlock()
			fmt.Fprintf(stderr, "Host complete: %s status=%s ports=%d (%d done)\n", host.Target.Input, host.Status, len(host.Ports), currentHosts)
		},
	}

	result, err := app.ScanWithProgress(ctx, cfg, progress)
	if !cfg.Silent {
		fmt.Fprintf(stderr, "Elapsed: %s\n", time.Since(start).Round(time.Millisecond))
	}
	return result, err
}

func writeOutputs(stdout io.Writer, result goscan.Report, cfg app.Config) error {
	wroteStdout := false
	if cfg.OutputText != "" {
		if err := writeFile(cfg.OutputText, func(w io.Writer) error { return report.WriteText(w, result) }); err != nil {
			return err
		}
	}
	if cfg.OutputJSON != "" {
		if err := writeFile(cfg.OutputJSON, func(w io.Writer) error { return report.WriteJSON(w, result) }); err != nil {
			return err
		}
	}
	if cfg.OutputCSV != "" {
		if err := writeFile(cfg.OutputCSV, func(w io.Writer) error { return report.WriteCSV(w, result) }); err != nil {
			return err
		}
	}
	if cfg.OutputText == "" && cfg.OutputJSON == "" && cfg.OutputCSV == "" {
		wroteStdout = true
		if cfg.JSON {
			return report.WriteJSON(stdout, result)
		}
		return report.WriteText(stdout, result)
	}
	if cfg.JSON && !wroteStdout {
		return report.WriteJSON(stdout, result)
	}
	return nil
}

func writeFile(path string, write func(io.Writer) error) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return write(file)
}

func filterOpen(result goscan.Report) goscan.Report {
	targets := result.Targets[:0]
	for i := range result.Targets {
		ports := result.Targets[i].Ports[:0]
		for _, port := range result.Targets[i].Ports {
			if port.State == goscan.PortOpen {
				ports = append(ports, port)
			}
		}
		result.Targets[i].Ports = ports
		if len(ports) > 0 {
			targets = append(targets, result.Targets[i])
		}
	}
	result.Targets = targets
	return result
}

func splitScanArgs(args []string) ([]string, []string) {
	valueFlags := map[string]struct{}{
		"-p": {}, "--p": {}, "-ports": {}, "--ports": {},
		"-timeout": {}, "--timeout": {},
		"-concurrency": {}, "--concurrency": {},
		"-port-workers": {}, "--port-workers": {},
		"-top-ports": {}, "--top-ports": {},
		"-host-workers": {}, "--host-workers": {},
		"-host-concurrency": {}, "--host-concurrency": {},
		"-banner-limit": {}, "--banner-limit": {},
		"-exclude-ports": {}, "--exclude-ports": {},
		"-oT": {}, "--oT": {}, "-oJ": {}, "--oJ": {}, "-oC": {}, "--oC": {},
	}

	var flagArgs []string
	var targets []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			targets = append(targets, args[i+1:]...)
			break
		}
		if arg == "-p-" {
			flagArgs = append(flagArgs, "-p", "-p-")
			continue
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
	fmt.Fprintln(w, "  goscan scan <target...> -p- --open")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  goscan scan 127.0.0.1 -Pn -p 22,80,443")
	fmt.Fprintln(w, "  goscan scan 192.168.1.0/24 --top-ports 100 --exclude-ports 25,137-139")
	fmt.Fprintln(w, "  goscan scan 127.0.0.1 -Pn -p- --open -oT scan.txt -oJ scan.json -oC scan.csv")
}
