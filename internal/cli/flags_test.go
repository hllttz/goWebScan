package cli

import (
	"bytes"
	"testing"
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
	flagArgs, targets := splitScanArgs([]string{"127.0.0.1", "-Pn", "-p", "22", "--host-workers=2"})
	if len(targets) != 1 || targets[0] != "127.0.0.1" {
		t.Fatalf("targets = %v", targets)
	}
	if len(flagArgs) != 4 {
		t.Fatalf("flag args = %v", flagArgs)
	}
}
