package runstore

import (
	"context"
	"testing"

	"goscan/pkg/goscan"
)

func TestStoreLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store := New()
	run := store.Create(cancel)
	if run.ID == "" {
		t.Fatal("expected run id")
	}
	if run.Status != StatusPending {
		t.Fatalf("got %s, want %s", run.Status, StatusPending)
	}

	store.Start(run.ID)
	store.AddHostResult(run.ID, goscan.HostResult{
		Target: goscan.Target{Input: "127.0.0.1"},
		Status: goscan.HostUp,
		Ports:  []goscan.PortResult{{State: goscan.PortOpen}},
	})

	got, ok := store.Get(run.ID)
	if !ok {
		t.Fatal("missing run")
	}
	if got.Summary.Hosts != 1 || got.Summary.Open != 1 {
		t.Fatalf("bad summary: %+v", got.Summary)
	}

	store.Finish(run.ID, got.Report, nil)
	got, _ = store.Get(run.ID)
	if got.Status != StatusCompleted {
		t.Fatalf("got %s, want %s", got.Status, StatusCompleted)
	}
	if got.Report.Targets == nil {
		t.Fatal("targets should be an empty slice, not nil")
	}

	_ = ctx
}

func TestStoreCancel(t *testing.T) {
	called := false
	store := New()
	run := store.Create(func() { called = true })
	if !store.Cancel(run.ID) {
		t.Fatal("cancel returned false")
	}
	if !called {
		t.Fatal("cancel func was not called")
	}
}
