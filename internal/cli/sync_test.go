package cli

import (
	"context"
	"errors"
	"testing"
)

func TestSyncAdminAfterInit(t *testing.T) {
	a, fake, _ := newTestApp(t)
	remoteURL := bareRepo(t)
	flags := &initFlags{
		owner:    "GonzaloAlvarez",
		repo:     "kauket-store",
		private:  true,
		remote:   remoteURL,
		noGitHub: true,
		yes:      true,
	}
	if err := runInit(context.Background(), a, flags); err != nil {
		t.Fatalf("init: %v", err)
	}
	fake.Lines = nil
	if err := runSync(context.Background(), a); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(fake.Lines) != 1 || fake.Lines[0] != "synced" {
		t.Fatalf("want 'synced', got %v", fake.Lines)
	}
}

func TestSyncUninitializedFails(t *testing.T) {
	a, _, _ := newTestApp(t)
	err := runSync(context.Background(), a)
	if err == nil {
		t.Fatalf("expected error on uninitialized sync")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %d", exitErr.Code)
	}
}
