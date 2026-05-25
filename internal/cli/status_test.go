package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/ui"
)

func TestStatusUninitialized(t *testing.T) {
	a, fake, _ := newTestApp(t)
	if err := runStatus(a); err != nil {
		t.Fatalf("runStatus: %v", err)
	}
	if len(fake.Lines) != 1 || fake.Lines[0] != "role: uninitialized" {
		t.Fatalf("want 'role: uninitialized', got %v", fake.Lines)
	}
}

func TestStatusAdminAfterInit(t *testing.T) {
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
	if err := runStatus(a); err != nil {
		t.Fatalf("status: %v", err)
	}
	wantLines := []string{
		"role: admin",
		"store: GonzaloAlvarez/kauket-store",
		"secrets: 0",
		"hosts: 0",
		"pending_requests: 0",
	}
	if len(fake.Lines) != len(wantLines) {
		t.Fatalf("expected %d lines, got %d: %v", len(wantLines), len(fake.Lines), fake.Lines)
	}
	for i, want := range wantLines {
		if fake.Lines[i] != want {
			t.Fatalf("line %d: want %q got %q", i, want, fake.Lines[i])
		}
	}
}

func TestStatusClient(t *testing.T) {
	a, _, home := newTestApp(t)
	a.UI = &ui.Fake{}
	fake := a.UI.(*ui.Fake)
	clientCfg := &config.Client{
		Schema:  config.ConfigSchema,
		Role:    config.RoleClient,
		StoreID: "ks_clienttest",
		Host: config.HostInfo{
			ID:           "h_clienttest1234",
			DisplayName:  "test-machine",
			IdentityPath: "identities/host.txt",
		},
		Repo: config.DefaultRepoInfo("GonzaloAlvarez", "kauket-store"),
	}
	if err := config.SaveClient(home, clientCfg); err != nil {
		t.Fatalf("save client: %v", err)
	}
	if err := runStatus(a); err != nil {
		t.Fatalf("status: %v", err)
	}
	want := []string{
		"role: client",
		"store: GonzaloAlvarez/kauket-store",
		"host_id: h_clienttest1234",
		"bundle: absent",
	}
	for i, w := range want {
		if fake.Lines[i] != w {
			t.Fatalf("line %d: want %q got %q", i, w, fake.Lines[i])
		}
	}
	if !strings.HasPrefix(fake.Lines[4], "last_sync: ") {
		t.Fatalf("expected last_sync line, got %q", fake.Lines[4])
	}
}
