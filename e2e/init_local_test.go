//go:build e2e

package e2e_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInitLocalE2E(t *testing.T) {
	bin := buildBinary(t)

	root := t.TempDir()
	adminHome := filepath.Join(root, "admin-home")
	kauketHome := filepath.Join(adminHome, ".config", "kauket")
	bareDir := filepath.Join(root, "bare-remote.git")
	recoveryOut := filepath.Join(root, "recovery")
	if err := os.MkdirAll(adminHome, 0o700); err != nil {
		t.Fatalf("mkdir admin home: %v", err)
	}
	remoteURL := setupBareRemote(t, bareDir)

	res := runKauket(t, bin, kauketHome, adminHome, "init", "--remote", remoteURL, "--no-github", "--recovery-out", recoveryOut, "--yes")
	if res.err != nil {
		t.Fatalf("init failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "initialized kauket v2 store") {
		t.Fatalf("expected stdout to contain 'initialized kauket v2 store', got: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "founder identity i_") {
		t.Fatalf("expected stdout to contain founder identity i_, got: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "recovery key pair written to "+recoveryOut) {
		t.Fatalf("expected stdout to mention recovery dir, got: %q", res.stdout)
	}

	adminKauketHome := filepath.Join(kauketHome, "admin")
	wantFiles := []string{
		filepath.Join(adminKauketHome, "config.json"),
		filepath.Join(adminKauketHome, "identities", "admin.txt"),
		filepath.Join(adminKauketHome, "identities", "sign.key"),
		filepath.Join(adminKauketHome, "repo", "store.json"),
		filepath.Join(adminKauketHome, "repo", "store.json.sig"),
		filepath.Join(recoveryOut, "recovery-age.txt"),
		filepath.Join(recoveryOut, "recovery-sign.key"),
	}
	for _, p := range wantFiles {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected file %s missing: %v", p, err)
		}
	}

	if runtime.GOOS != "windows" {
		assertMode(t, filepath.Join(adminKauketHome, "config.json"), 0o600)
		assertMode(t, filepath.Join(adminKauketHome, "identities", "admin.txt"), 0o600)
		assertMode(t, filepath.Join(recoveryOut, "recovery-age.txt"), 0o600)
	}

	res = runKauket(t, bin, kauketHome, adminHome, "init", "--remote", remoteURL, "--no-github", "--recovery-out", recoveryOut, "--yes")
	if res.err == nil {
		t.Fatalf("re-init should be refused on an existing v2 store; stdout:%s", res.stdout)
	}
	if !strings.Contains(res.stderr, "already holds a v2 store") {
		t.Fatalf("expected re-init refusal message, got stderr: %q", res.stderr)
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
		"schema: 2",
		"nodes readable: 1",
		"entries readable: 0",
	}
	for _, line := range wantLines {
		if !strings.Contains(res.stdout, line) {
			t.Fatalf("status missing %q; got %q", line, res.stdout)
		}
	}

	res = runKauket(t, bin, kauketHome, adminHome, "verify")
	if res.err != nil {
		t.Fatalf("verify failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "verified 1 nodes, 0 entries") {
		t.Fatalf("verify output: %q", res.stdout)
	}

	res = runKauket(t, bin, kauketHome, adminHome, "sync")
	if res.err != nil {
		t.Fatalf("sync failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if strings.TrimSpace(res.stdout) != "synced" {
		t.Fatalf("expected 'synced', got: %q", res.stdout)
	}
}
