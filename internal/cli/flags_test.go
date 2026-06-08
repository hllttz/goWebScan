package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/hllttz/goWebScan/pkg/goscan"
)

func TestExecuteScanSupportsPnSVAndWorkers(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Execute([]string{
		"scan",
		"127.0.0.1",
		"-Pn",
		"-sV",
		"-p", "1",
		"--host-workers", "2",
		"--port-workers", "3",
		"--timeout", "1ms",
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code %d, stderr=%s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"reason": "discovery_skipped"`)) {
		t.Fatalf("stdout missing discovery reason: %s", stdout.String())
	}
}

func TestSplitScanArgsAllowsFlagsAfterTargets(t *testing.T) {
	flagArgs, targets := splitScanArgs([]string{"127.0.0.1", "-Pn", "-p", "22", "--host-workers=2", "--exclude-ports", "80", "-oT", "out.txt"})
	if len(targets) != 1 || targets[0] != "127.0.0.1" {
		t.Fatalf("targets = %v", targets)
	}
	if len(flagArgs) != 8 {
		t.Fatalf("flag args = %v", flagArgs)
	}
}

func TestSplitScanArgsSupportsDashPShortcut(t *testing.T) {
	flagArgs, targets := splitScanArgs([]string{"127.0.0.1", "-p-"})
	if len(targets) != 1 || targets[0] != "127.0.0.1" {
		t.Fatalf("targets = %v", targets)
	}
	want := []string{"-p", "-p-"}
	if len(flagArgs) != len(want) {
		t.Fatalf("flag args = %v", flagArgs)
	}
	for i := range want {
		if flagArgs[i] != want[i] {
			t.Fatalf("flag args = %v, want %v", flagArgs, want)
		}
	}
}

func TestExecuteScanWritesOutputFilesAndSilentProgress(t *testing.T) {
	dir := t.TempDir()
	textPath := filepath.Join(dir, "scan.txt")
	jsonPath := filepath.Join(dir, "scan.json")
	csvPath := filepath.Join(dir, "scan.csv")
	var stdout, stderr bytes.Buffer
	code := Execute([]string{
		"scan",
		"127.0.0.1",
		"-Pn",
		"-p", "1",
		"--timeout", "1ms",
		"--silent",
		"-oT", textPath,
		"-oJ", jsonPath,
		"-oC", csvPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code %d, stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected silent stderr, got %q", stderr.String())
	}
	for _, path := range []string{textPath, jsonPath, csvPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("missing output %s: %v", path, err)
		}
		if info.Size() == 0 {
			t.Fatalf("empty output %s", path)
		}
	}
}

func TestFilterOpen(t *testing.T) {
	report := goscan.Report{Targets: []goscan.HostResult{{
		Ports: []goscan.PortResult{
			{State: goscan.PortClosed},
			{State: goscan.PortOpen},
			{State: goscan.PortFiltered},
		},
	}}}
	filtered := filterOpen(report)
	if len(filtered.Targets[0].Ports) != 1 {
		t.Fatalf("got %d ports, want 1", len(filtered.Targets[0].Ports))
	}
	if filtered.Targets[0].Ports[0].State != goscan.PortOpen {
		t.Fatalf("got %s, want open", filtered.Targets[0].Ports[0].State)
	}
}
