//go:build e2e

package e2e_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "kauket")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/kauket")
	cmd.Dir = root
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, string(out))
	}
	return bin
}

func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("could not find go.mod above " + wd)
		}
		dir = parent
	}
}

func setupBareRemote(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir bare: %v", err)
	}
	repo, err := gogit.PlainInit(dir, true)
	if err != nil {
		t.Fatalf("bare init: %v", err)
	}
	headRef := plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.NewBranchReferenceName("main"))
	if err := repo.Storer.SetReference(headRef); err != nil {
		t.Fatalf("set HEAD: %v", err)
	}
	return "file://" + dir
}

type runResult struct {
	stdout string
	stderr string
	err    error
}

func runKauket(t *testing.T, bin, kauketHome, home string, args ...string) runResult {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(),
		"KAUKET_HOME="+kauketHome,
		"HOME="+home,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return runResult{stdout: stdout.String(), stderr: stderr.String(), err: err}
}

func TestInitLocalE2E(t *testing.T) {
	bin := buildBinary(t)

	root := t.TempDir()
	adminHome := filepath.Join(root, "admin-home")
	kauketHome := filepath.Join(adminHome, ".config", "kauket")
	bareDir := filepath.Join(root, "bare-remote.git")
	if err := os.MkdirAll(adminHome, 0o700); err != nil {
		t.Fatalf("mkdir admin home: %v", err)
	}
	remoteURL := setupBareRemote(t, bareDir)

	res := runKauket(t, bin, kauketHome, adminHome, "init", "--remote", remoteURL, "--no-github", "--yes")
	if res.err != nil {
		t.Fatalf("init failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "initialized kauket store") {
		t.Fatalf("expected stdout to contain 'initialized kauket store', got: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "admin recipient ar_") {
		t.Fatalf("expected stdout to contain admin recipient ar_, got: %q", res.stdout)
	}

	wantFiles := []string{
		filepath.Join(kauketHome, "config.json"),
		filepath.Join(kauketHome, "identities", "admin.txt"),
		filepath.Join(kauketHome, "repo", "repo.json"),
		filepath.Join(kauketHome, "repo", "admin", "vault.age"),
		filepath.Join(kauketHome, "repo", "bundles", ".keep"),
		filepath.Join(kauketHome, "repo", "requests", ".keep"),
	}
	for _, p := range wantFiles {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected file %s missing: %v", p, err)
		}
	}

	if runtime.GOOS != "windows" {
		assertMode(t, filepath.Join(kauketHome, "config.json"), 0o600)
		assertMode(t, filepath.Join(kauketHome, "identities", "admin.txt"), 0o600)
	}

	res = runKauket(t, bin, kauketHome, adminHome, "init", "--remote", remoteURL, "--no-github", "--yes")
	if res.err != nil {
		t.Fatalf("re-init failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "initialized kauket store") {
		t.Fatalf("expected reattach to print initialized kauket store, got: %q", res.stdout)
	}

	res = runKauket(t, bin, kauketHome, adminHome, "version")
	if res.err != nil {
		t.Fatalf("version failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.HasPrefix(res.stdout, "kauket ") {
		t.Fatalf("version stdout should start with 'kauket ', got: %q", res.stdout)
	}

	res = runKauket(t, bin, kauketHome, adminHome, "status")
	if res.err != nil {
		t.Fatalf("status failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	wantLines := []string{
		"role: admin",
		"store: GonzaloAlvarez/kauket-store",
		"secrets: 0",
		"hosts: 0",
		"pending_requests: 0",
	}
	for _, line := range wantLines {
		if !strings.Contains(res.stdout, line) {
			t.Fatalf("status missing %q; got %q", line, res.stdout)
		}
	}

	res = runKauket(t, bin, kauketHome, adminHome, "sync")
	if res.err != nil {
		t.Fatalf("sync failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if strings.TrimSpace(res.stdout) != "synced" {
		t.Fatalf("expected 'synced', got: %q", res.stdout)
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
