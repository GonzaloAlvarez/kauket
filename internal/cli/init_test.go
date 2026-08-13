package cli

import (
	"context"
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
	recoveryOut := filepath.Join(t.TempDir(), "recovery")

	flags := &initFlags{
		owner:       "GonzaloAlvarez",
		repo:        "kauket-store",
		private:     true,
		remote:      remoteURL,
		noGitHub:    true,
		yes:         true,
		recoveryOut: recoveryOut,
	}
	if err := runInit(context.Background(), a, flags); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	lines := make([]string, 0, len(fake.Lines))
	for _, l := range fake.Lines {
		if strings.HasPrefix(l, "store trust-anchor fingerprint:") || strings.HasPrefix(l, "share it out of band") {
			continue
		}
		lines = append(lines, l)
	}
	if len(lines) != 4 {
		t.Fatalf("expected 4 output lines, got %d: %v", len(lines), fake.Lines)
	}
	if lines[0] != "initialized kauket v2 store GonzaloAlvarez/kauket-store" {
		t.Fatalf("first line: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "founder identity i_") || !strings.HasSuffix(lines[1], " created") {
		t.Fatalf("second line: %q", lines[1])
	}
	if lines[2] != "recovery key pair written to "+recoveryOut {
		t.Fatalf("third line: %q", lines[2])
	}
	if !strings.Contains(lines[3], "OFFLINE") {
		t.Fatalf("fourth line: %q", lines[3])
	}

	adminHome := config.RoleHome(home, config.RoleAdmin)
	wantFiles := []string{
		filepath.Join(adminHome, "config.json"),
		filepath.Join(adminHome, "identities", "admin.txt"),
		filepath.Join(adminHome, "identities", "sign.key"),
		filepath.Join(adminHome, "repo", "store.json"),
		filepath.Join(adminHome, "repo", "store.json.sig"),
		filepath.Join(recoveryOut, "recovery-age.txt"),
		filepath.Join(recoveryOut, "recovery-sign.key"),
	}
	for _, p := range wantFiles {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected file %s missing: %v", p, err)
		}
	}

	if runtime.GOOS != "windows" {
		assertMode(t, filepath.Join(adminHome, "config.json"), 0o600)
		assertMode(t, filepath.Join(adminHome, "identities", "admin.txt"), 0o600)
		assertMode(t, filepath.Join(adminHome, "identities", "sign.key"), 0o600)
		assertMode(t, filepath.Join(adminHome, "identities"), 0o700)
		assertMode(t, filepath.Join(recoveryOut, "recovery-age.txt"), 0o600)
	}

	role, err := config.PeekRole(adminHome)
	if err != nil {
		t.Fatalf("peek role: %v", err)
	}
	if role != config.RoleAdmin {
		t.Fatalf("expected role admin, got %q", role)
	}
	cfg, err := config.LoadAdmin(adminHome)
	if err != nil {
		t.Fatalf("load admin: %v", err)
	}
	if cfg.StoreID == "" {
		t.Fatalf("store id empty")
	}
	if cfg.Admin.IdentityPath != filepath.Join("identities", "admin.txt") {
		t.Fatalf("identity path unexpected: %q", cfg.Admin.IdentityPath)
	}
	if cfg.V2 == nil || !strings.HasPrefix(cfg.V2.IdentityID, "i_") || cfg.V2.SignKeyPath != filepath.Join("identities", "sign.key") {
		t.Fatalf("v2 config: %+v", cfg.V2)
	}
}

func TestInitRefusesExistingV2Store(t *testing.T) {
	a, fake, home := newTestApp(t)
	remoteURL := bareRepo(t)

	flags := &initFlags{
		owner:       "GonzaloAlvarez",
		repo:        "kauket-store",
		private:     true,
		remote:      remoteURL,
		noGitHub:    true,
		yes:         true,
		recoveryOut: filepath.Join(t.TempDir(), "recovery"),
	}
	if err := runInit(context.Background(), a, flags); err != nil {
		t.Fatalf("first init: %v", err)
	}
	adminHome := config.RoleHome(home, config.RoleAdmin)
	cfg1, err := config.LoadAdmin(adminHome)
	if err != nil {
		t.Fatalf("load first: %v", err)
	}
	fake.Lines = nil

	err = runInit(context.Background(), a, flags)
	if err == nil || !strings.Contains(err.Error(), "already holds a v2 store") {
		t.Fatalf("second init err = %v, want already-holds-v2 refusal", err)
	}

	cfg2, err := config.LoadAdmin(adminHome)
	if err != nil {
		t.Fatalf("load second: %v", err)
	}
	if cfg1.StoreID != cfg2.StoreID {
		t.Fatalf("store id changed after refused re-init: %q -> %q", cfg1.StoreID, cfg2.StoreID)
	}
	if cfg1.V2.IdentityID != cfg2.V2.IdentityID {
		t.Fatalf("identity id changed after refused re-init: %q -> %q", cfg1.V2.IdentityID, cfg2.V2.IdentityID)
	}
}

func TestInitRefusesSSHRemoteWithoutNoGitHub(t *testing.T) {
	a, _, _ := newTestApp(t)
	flags := &initFlags{
		owner:       "GonzaloAlvarez",
		repo:        "kauket-store",
		private:     true,
		remote:      "git@github.com:GonzaloAlvarez/kauket-store.git",
		noGitHub:    false,
		yes:         true,
		recoveryOut: filepath.Join(t.TempDir(), "recovery"),
	}
	err := runInit(context.Background(), a, flags)
	if err == nil {
		t.Fatalf("expected SSH remote refusal")
	}
	if !strings.Contains(err.Error(), "SSH") {
		t.Fatalf("expected SSH mention, got %q", err.Error())
	}
}

func TestInitV2ObjectsAreEncrypted(t *testing.T) {
	fx, _ := initV2Fixture(t)
	adminHome := config.RoleHome(fx.home, config.RoleAdmin)
	dir := objectsDir(config.RepoDir(adminHome))
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("objects dir: %v entries, err %v", len(entries), err)
	}
	for _, e := range entries {
		ct, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read object %s: %v", e.Name(), err)
		}
		if len(ct) == 0 {
			t.Fatalf("object %s empty", e.Name())
		}
		if !strings.Contains(string(ct), "age-encryption") {
			t.Fatalf("object %s lacks age header marker; first 64 bytes: %q", e.Name(), limitString(string(ct), 64))
		}
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
