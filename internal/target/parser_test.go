package target

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParseTargetsCIDR(t *testing.T) {
	targets, err := ParseTargets(context.Background(), []string{"192.0.2.0/30"})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
	if got := targets[0].Addresses[0].String(); got != "192.0.2.1" {
		t.Fatalf("first address = %s, want 192.0.2.1", got)
	}
	if got := targets[1].Addresses[0].String(); got != "192.0.2.2" {
		t.Fatalf("second address = %s, want 192.0.2.2", got)
	}
}

func TestParseTargetsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("# comment\n127.0.0.1\n192.0.2.1\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := ParseTargets(context.Background(), []string{path})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
}

func TestParseTargetsMultiple(t *testing.T) {
	targets, err := ParseTargets(context.Background(), []string{"127.0.0.1", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
}
