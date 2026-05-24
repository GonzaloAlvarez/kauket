package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHome_DefaultsToUserConfigDir(t *testing.T) {
	t.Setenv("KAUKET_HOME", "")
	base, err := os.UserConfigDir()
	if err != nil {
		t.Skipf("user config dir unavailable: %v", err)
	}
	got, err := Home()
	if err != nil {
		t.Fatalf("Home() error: %v", err)
	}
	want := filepath.Join(base, "kauket")
	if got != want {
		t.Fatalf("Home() = %q, want %q", got, want)
	}
}

func TestHome_AbsoluteKaukenHome(t *testing.T) {
	dir := t.TempDir()
	want := filepath.Join(dir, "kauket-x")
	t.Setenv("KAUKET_HOME", want)
	got, err := Home()
	if err != nil {
		t.Fatalf("Home() error: %v", err)
	}
	if got != want {
		t.Fatalf("Home() = %q, want %q", got, want)
	}
}

func TestHome_RelativeKaukenHomeResolved(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Setenv("KAUKET_HOME", "./relative/kauket")
	got, err := Home()
	if err != nil {
		t.Fatalf("Home() error: %v", err)
	}
	wantBase, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("evalsymlinks: %v", err)
	}
	gotResolved, err := filepath.EvalSymlinks(filepath.Dir(filepath.Dir(got)))
	if err != nil {
		gotResolved = filepath.Dir(filepath.Dir(got))
	}
	if gotResolved != wantBase {
		t.Fatalf("Home() = %q, expected absolute path under %q (resolved: %q)", got, wantBase, gotResolved)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("Home() = %q, expected absolute path", got)
	}
	if filepath.Base(got) != "kauket" {
		t.Fatalf("Home() = %q, expected last segment 'kauket'", got)
	}
}

func TestEnsureHome_CreatesDirWith0700(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "kauket")
	t.Setenv("KAUKET_HOME", home)
	got, err := EnsureHome()
	if err != nil {
		t.Fatalf("EnsureHome() error: %v", err)
	}
	if got != home {
		t.Fatalf("EnsureHome() = %q, want %q", got, home)
	}
	info, err := os.Stat(home)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0700 {
		t.Fatalf("home mode = %o, want 0700", mode)
	}
}

func TestEnsureIdentitiesDir(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "kauket")
	t.Setenv("KAUKET_HOME", home)
	if _, err := EnsureHome(); err != nil {
		t.Fatalf("EnsureHome: %v", err)
	}
	if err := EnsureIdentitiesDir(home); err != nil {
		t.Fatalf("EnsureIdentitiesDir: %v", err)
	}
	info, err := os.Stat(IdentitiesDir(home))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0700 {
		t.Fatalf("identities dir mode = %o, want 0700", mode)
	}
}

func TestEnsureGitDir(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "kauket")
	t.Setenv("KAUKET_HOME", home)
	if _, err := EnsureHome(); err != nil {
		t.Fatalf("EnsureHome: %v", err)
	}
	if err := EnsureGitDir(home); err != nil {
		t.Fatalf("EnsureGitDir: %v", err)
	}
	info, err := os.Stat(GitDir(home))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0700 {
		t.Fatalf("git dir mode = %o, want 0700", mode)
	}
}

func TestEnsureStateDir(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "kauket")
	t.Setenv("KAUKET_HOME", home)
	if _, err := EnsureHome(); err != nil {
		t.Fatalf("EnsureHome: %v", err)
	}
	if err := EnsureStateDir(home); err != nil {
		t.Fatalf("EnsureStateDir: %v", err)
	}
	info, err := os.Stat(StateDir(home))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0700 {
		t.Fatalf("state dir mode = %o, want 0700", mode)
	}
}

func TestPathHelpers(t *testing.T) {
	home := "/tmp/kauket-paths"
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"ConfigPath", ConfigPath(home), filepath.Join(home, "config.json")},
		{"IdentitiesDir", IdentitiesDir(home), filepath.Join(home, "identities")},
		{"AdminIdentityPath", AdminIdentityPath(home), filepath.Join(home, "identities", "admin.txt")},
		{"HostIdentityPath", HostIdentityPath(home), filepath.Join(home, "identities", "host.txt")},
		{"GitDir", GitDir(home), filepath.Join(home, "git")},
		{"DeployKeyPath", DeployKeyPath(home), filepath.Join(home, "git", "deploy_key")},
		{"DeployKeyPubPath", DeployKeyPubPath(home), filepath.Join(home, "git", "deploy_key.pub")},
		{"RepoDir", RepoDir(home), filepath.Join(home, "repo")},
		{"StateDir", StateDir(home), filepath.Join(home, "state")},
		{"InstalledStatePath", InstalledStatePath(home), filepath.Join(home, "state", "installed.json")},
		{"LockPath", LockPath(home), filepath.Join(home, "repo.lock")},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Setenv("KAUKET_REPO", "owner/repo")
	t.Setenv("KAUKET_REMOTE", "git@example.com:o/r.git")
	t.Setenv("KAUKET_NO_COLOR", "1")
	t.Setenv("KAUKET_DEBUG", "1")
	if EnvRepo() != "owner/repo" {
		t.Errorf("EnvRepo = %q", EnvRepo())
	}
	if EnvRemote() != "git@example.com:o/r.git" {
		t.Errorf("EnvRemote = %q", EnvRemote())
	}
	if !EnvNoColor() {
		t.Errorf("EnvNoColor = false")
	}
	if !EnvDebug() {
		t.Errorf("EnvDebug = false")
	}
	t.Setenv("KAUKET_NO_COLOR", "")
	t.Setenv("KAUKET_DEBUG", "")
	if EnvNoColor() {
		t.Errorf("EnvNoColor empty = true")
	}
	if EnvDebug() {
		t.Errorf("EnvDebug empty = true")
	}
}
