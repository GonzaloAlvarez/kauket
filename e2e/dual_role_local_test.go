//go:build e2e

package e2e_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDualRoleLocalE2E(t *testing.T) {
	bin := buildBinary(t)

	root := mustResolvedTempRoot(t)
	home := filepath.Join(root, "dual-home")
	kauketHome := filepath.Join(home, ".config", "kauket")
	bareDir := filepath.Join(root, "bare-remote.git")
	mustMkdir(t, home, 0o700)
	remoteURL := setupBareRemote(t, bareDir)

	res := runKauket(t, bin, kauketHome, home, "init", "--remote", remoteURL, "--no-github", "--recovery-out", filepath.Join(root, "recovery"), "--yes")
	if res.err != nil {
		t.Fatalf("init: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	srcKey := filepath.Join(home, "src", "main_private_key.pem")
	generateEd25519KeyFile(t, srcKey)
	res = runKauket(t, bin, kauketHome, home, "add", "ssh.main_private_key", srcKey)
	if res.err != nil {
		t.Fatalf("add: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, kauketHome, home, "enroll", "--remote", remoteURL, "--request", "ssh", "--name", "dualhost", "--yes")
	if res.err != nil {
		t.Fatalf("enroll: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, kauketHome, home, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, kauketHome, home, "get", "ssh.main_private_key")
	if res.err != nil {
		t.Fatalf("get: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	want, err := os.ReadFile(srcKey)
	if err != nil {
		t.Fatalf("read source key: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(home, ".ssh", "main_private_key"))
	if err != nil {
		t.Fatalf("read installed key: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("installed key does not match source")
	}

	res = runKauket(t, bin, kauketHome, home, "status")
	if res.err != nil {
		t.Fatalf("status: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "role: admin") || !strings.Contains(res.stdout, "role: client") {
		t.Fatalf("status should show both roles, got: %q", res.stdout)
	}

	res = runKauket(t, bin, kauketHome, home, "sync")
	if res.err != nil {
		t.Fatalf("sync: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "synced admin") || !strings.Contains(res.stdout, "synced client") {
		t.Fatalf("sync should report both roles, got: %q", res.stdout)
	}

	for _, p := range []string{
		filepath.Join(kauketHome, "admin", "repo", "store.json"),
		filepath.Join(kauketHome, "client", "repo", "store.json"),
		filepath.Join(kauketHome, "admin", "repo.lock"),
		filepath.Join(kauketHome, "client", "repo.lock"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected per-role file %s: %v", p, err)
		}
	}

	forbidden := []string{"ssh.main_private_key", "main_private_key", "dualhost", "BEGIN OPENSSH"}
	for _, repo := range []string{
		filepath.Join(kauketHome, "admin", "repo"),
		filepath.Join(kauketHome, "client", "repo"),
	} {
		for _, term := range forbidden {
			if hits := grepRepo(t, repo, term); len(hits) != 0 {
				t.Fatalf("leak: term %q found in %s: %v", term, repo, hits)
			}
		}
	}
}
