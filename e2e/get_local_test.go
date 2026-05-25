//go:build e2e

package e2e_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGetLocalE2E(t *testing.T) {
	bin := buildBinary(t)

	root := t.TempDir()
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	root = resolvedRoot
	adminHome := filepath.Join(root, "admin-home")
	adminKauket := filepath.Join(adminHome, ".config", "kauket")
	clientHome := filepath.Join(root, "machine2-home")
	clientKauket := filepath.Join(clientHome, ".config", "kauket")
	bareDir := filepath.Join(root, "bare-remote.git")

	if err := os.MkdirAll(adminHome, 0o700); err != nil {
		t.Fatalf("mkdir admin home: %v", err)
	}
	if err := os.MkdirAll(clientHome, 0o700); err != nil {
		t.Fatalf("mkdir client home: %v", err)
	}
	remoteURL := setupBareRemote(t, bareDir)

	res := runKauket(t, bin, adminKauket, adminHome, "init", "--remote", remoteURL, "--no-github", "--yes")
	if res.err != nil {
		t.Fatalf("admin init failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	adminKeyPath := filepath.Join(adminHome, ".ssh", "main_private_key.pem")
	generateEd25519KeyFile(t, adminKeyPath)

	res = runKauket(t, bin, adminKauket, adminHome, "add", "ssh.main_private_key", adminKeyPath)
	if res.err != nil {
		t.Fatalf("admin add failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "enroll", "--remote", remoteURL, "--request", "ssh", "--name", "machine2", "--yes")
	if res.err != nil {
		t.Fatalf("enroll failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, adminKauket, adminHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "get", "ssh.main_private_key")
	if res.err != nil {
		t.Fatalf("get failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "syncing store") {
		t.Fatalf("expected 'syncing store' in stdout, got: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "creating ~/.ssh/main_private_key") {
		t.Fatalf("expected 'creating ~/.ssh/main_private_key' in stdout, got: %q", res.stdout)
	}

	clientKeyPath := filepath.Join(clientHome, ".ssh", "main_private_key")
	info, err := os.Stat(clientKeyPath)
	if err != nil {
		t.Fatalf("client key not installed: %v", err)
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("client key mode: got %o, want 0600", info.Mode().Perm())
		}
		dirInfo, err := os.Stat(filepath.Join(clientHome, ".ssh"))
		if err != nil {
			t.Fatalf("stat .ssh dir: %v", err)
		}
		if dirInfo.Mode().Perm() != 0o700 {
			t.Fatalf(".ssh dir mode: got %o, want 0700", dirInfo.Mode().Perm())
		}
	}
	adminContent, err := os.ReadFile(adminKeyPath)
	if err != nil {
		t.Fatalf("read admin key: %v", err)
	}
	clientContent, err := os.ReadFile(clientKeyPath)
	if err != nil {
		t.Fatalf("read client key: %v", err)
	}
	if string(adminContent) != string(clientContent) {
		t.Fatalf("admin and client key contents differ")
	}

	sshKeygen, err := exec.LookPath("ssh-keygen")
	if err == nil {
		out, err := exec.Command(sshKeygen, "-y", "-f", clientKeyPath).CombinedOutput()
		if err != nil {
			t.Fatalf("ssh-keygen round trip failed: %v\n%s", err, string(out))
		}
		if !strings.HasPrefix(strings.TrimSpace(string(out)), "ssh-ed25519 ") {
			t.Fatalf("expected ed25519 public key from ssh-keygen, got: %q", string(out))
		}
	}

	checkout := adminKauket + "/repo"
	forbidden := []string{
		"ssh.main_private_key",
		"main_private_key",
		"machine2",
		"BEGIN OPENSSH",
	}
	for _, term := range forbidden {
		hits := grepRepo(t, checkout, term)
		if len(hits) != 0 {
			t.Fatalf("forbidden term %q present in admin checkout: %v", term, hits)
		}
	}
}
