package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/ui"
)

func bareRepo(t *testing.T) string {
	t.Helper()
	bare := t.TempDir()
	repo, err := gogit.PlainInit(bare, true)
	if err != nil {
		t.Fatalf("bare init: %v", err)
	}
	headRef := plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.NewBranchReferenceName("main"))
	if err := repo.Storer.SetReference(headRef); err != nil {
		t.Fatalf("set bare HEAD: %v", err)
	}
	return "file://" + bare
}

func newTestApp(t *testing.T) (*app.App, *ui.Fake, string) {
	t.Helper()
	home := t.TempDir()
	f := &ui.Fake{}
	a := &app.App{
		UI:   f,
		Home: home,
	}
	return a, f, home
}

func TestInitFreshLocalRemoteWritesExpectedFiles(t *testing.T) {
	a, fake, home := newTestApp(t)
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
		t.Fatalf("runInit: %v", err)
	}

	if len(fake.Lines) != 2 {
		t.Fatalf("expected 2 output lines, got %d: %v", len(fake.Lines), fake.Lines)
	}
	if !strings.HasPrefix(fake.Lines[0], "initialized kauket store ") {
		t.Fatalf("first line %q does not start with initialized kauket store", fake.Lines[0])
	}
	if !strings.Contains(fake.Lines[0], "GonzaloAlvarez/kauket-store") {
		t.Fatalf("first line missing owner/repo: %q", fake.Lines[0])
	}
	if !strings.HasPrefix(fake.Lines[1], "admin recipient ar_") {
		t.Fatalf("second line %q does not start with admin recipient ar_", fake.Lines[1])
	}
	if !strings.HasSuffix(fake.Lines[1], " created") {
		t.Fatalf("second line %q does not end with created", fake.Lines[1])
	}

	wantFiles := []string{
		filepath.Join(home, "config.json"),
		filepath.Join(home, "identities", "admin.txt"),
		filepath.Join(home, "repo", "repo.json"),
		filepath.Join(home, "repo", "admin", "vault.age"),
		filepath.Join(home, "repo", "bundles", ".keep"),
		filepath.Join(home, "repo", "requests", ".keep"),
	}
	for _, p := range wantFiles {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected file %s missing: %v", p, err)
		}
	}

	if runtime.GOOS != "windows" {
		assertMode(t, filepath.Join(home, "config.json"), 0o600)
		assertMode(t, filepath.Join(home, "identities", "admin.txt"), 0o600)
		assertMode(t, filepath.Join(home, "identities"), 0o700)
	}

	role, err := config.PeekRole(home)
	if err != nil {
		t.Fatalf("peek role: %v", err)
	}
	if role != config.RoleAdmin {
		t.Fatalf("expected role admin, got %q", role)
	}
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		t.Fatalf("load admin: %v", err)
	}
	if cfg.StoreID == "" {
		t.Fatalf("store id empty")
	}
	if cfg.Admin.RecipientID == "" {
		t.Fatalf("admin recipient id empty")
	}
	if cfg.Admin.IdentityPath != filepath.Join("identities", "admin.txt") {
		t.Fatalf("identity path unexpected: %q", cfg.Admin.IdentityPath)
	}
}

func TestInitReattachIsIdempotent(t *testing.T) {
	a, fake, home := newTestApp(t)
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
		t.Fatalf("first init: %v", err)
	}
	cfg1, err := config.LoadAdmin(home)
	if err != nil {
		t.Fatalf("load first: %v", err)
	}
	fake.Lines = nil

	if err := runInit(context.Background(), a, flags); err != nil {
		t.Fatalf("second init: %v", err)
	}
	cfg2, err := config.LoadAdmin(home)
	if err != nil {
		t.Fatalf("load second: %v", err)
	}
	if cfg1.StoreID != cfg2.StoreID {
		t.Fatalf("store id changed between inits: %q -> %q", cfg1.StoreID, cfg2.StoreID)
	}
	if cfg1.Admin.RecipientID != cfg2.Admin.RecipientID {
		t.Fatalf("recipient id changed between inits: %q -> %q", cfg1.Admin.RecipientID, cfg2.Admin.RecipientID)
	}
	if len(fake.Lines) != 2 {
		t.Fatalf("expected 2 reattach lines, got %v", fake.Lines)
	}
	if !strings.Contains(fake.Lines[0], "initialized kauket store") {
		t.Fatalf("reattach first line unexpected: %q", fake.Lines[0])
	}
}

func TestInitRefusesClientRole(t *testing.T) {
	a, _, home := newTestApp(t)
	clientCfg := &config.Client{
		Schema:  config.ConfigSchema,
		Role:    config.RoleClient,
		StoreID: "ks_test",
		Host: config.HostInfo{
			ID:           "h_test1234567890",
			IdentityPath: "identities/host.txt",
		},
		Repo: config.DefaultRepoInfo("GonzaloAlvarez", "kauket-store"),
	}
	if err := config.SaveClient(home, clientCfg); err != nil {
		t.Fatalf("save client: %v", err)
	}
	flags := &initFlags{
		owner:    "GonzaloAlvarez",
		repo:     "kauket-store",
		private:  true,
		remote:   bareRepo(t),
		noGitHub: true,
		yes:      true,
	}
	err := runInit(context.Background(), a, flags)
	if err == nil {
		t.Fatalf("expected client role refusal")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %d", exitErr.Code)
	}
	if !strings.Contains(err.Error(), "client") {
		t.Fatalf("expected client mention, got %q", err.Error())
	}
}

func TestInitRefusesSSHRemoteWithoutNoGitHub(t *testing.T) {
	a, _, _ := newTestApp(t)
	flags := &initFlags{
		owner:    "GonzaloAlvarez",
		repo:     "kauket-store",
		private:  true,
		remote:   "git@github.com:GonzaloAlvarez/kauket-store.git",
		noGitHub: false,
		yes:      true,
	}
	err := runInit(context.Background(), a, flags)
	if err == nil {
		t.Fatalf("expected SSH remote refusal")
	}
	if !strings.Contains(err.Error(), "SSH") {
		t.Fatalf("expected SSH mention, got %q", err.Error())
	}
}

func TestInitAdminVaultIsEncryptedToRecipient(t *testing.T) {
	a, _, home := newTestApp(t)
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
	vaultPath := filepath.Join(home, "repo", "admin", "vault.age")
	ct, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read vault: %v", err)
	}
	if len(ct) == 0 {
		t.Fatalf("vault file empty")
	}
	if !strings.Contains(string(ct), "age-encryption") {
		t.Fatalf("vault does not contain age header marker; first 64 bytes: %q", limitString(string(ct), 64))
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	got := info.Mode().Perm()
	if got != want {
		t.Fatalf("mode for %s: want %v, got %v", path, want, got)
	}
}

func limitString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
