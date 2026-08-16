package cli

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/gonzaloalvarez/kauket/internal/config"
)

func TestListAdminOutput(t *testing.T) {
	a, fake, _ := initAdminFixture(t)

	keyPath := writeSSHKeyFixture(t)
	if err := runAdd(context.Background(), a, &addFlags{}, "ssh.main_private_key", keyPath); err != nil {
		t.Fatalf("add 1: %v", err)
	}
	fake.Lines = nil
	awsKey := writeSSHKeyFixture(t)
	if err := runAdd(context.Background(), a, &addFlags{}, "aws.primary_account.key_file", awsKey); err != nil {
		t.Fatalf("add 2: %v", err)
	}
	fake.Lines = nil

	if err := runList(context.Background(), a, ""); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(fake.Lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(fake.Lines), fake.Lines)
	}
	want := []string{
		"aws.primary_account.key_file",
		"ssh.main_private_key",
	}
	for i, w := range want {
		if fake.Lines[i] != w {
			t.Fatalf("line %d: want %q got %q", i, w, fake.Lines[i])
		}
	}
}

func TestListAdminEmpty(t *testing.T) {
	a, fake, _ := initAdminFixture(t)
	if err := runList(context.Background(), a, ""); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(fake.Lines) != 0 {
		t.Fatalf("expected zero lines for empty store, got %v", fake.Lines)
	}
}

func TestListClientNoStoreClone(t *testing.T) {
	a, _, home := newTestApp(t)
	clientHome := config.RoleHome(home, config.RoleClient)
	clientCfg := &config.Client{
		Schema:  config.ConfigSchema,
		Role:    config.RoleClient,
		StoreID: "ks_listtest",
		Host: config.HostInfo{
			ID:           "h_listtest12345678",
			DisplayName:  "listtest",
			IdentityPath: filepath.Join("identities", "host.txt"),
		},
		Repo: config.RepoInfo{RemoteHTTPS: "file:///nonexistent-kauket-remote"},
	}
	if err := config.SaveClient(clientHome, clientCfg); err != nil {
		t.Fatalf("save client: %v", err)
	}
	err := runList(context.Background(), a, "")
	if err == nil {
		t.Fatalf("expected error when no store clone present and remote unreachable")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitSync {
		t.Fatalf("expected ExitSync=%d, got %d", ExitSync, exitErr.Code)
	}
}

func TestListUninitialized(t *testing.T) {
	a, _, _ := newTestApp(t)
	err := runList(context.Background(), a, "")
	if err == nil {
		t.Fatalf("expected error when uninitialized")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %d", exitErr.Code)
	}
}
