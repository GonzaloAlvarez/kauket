//go:build e2e

package e2e_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2WriteLocalE2E(t *testing.T) {
	bin := buildBinary(t)
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")

	root := mustResolvedTempRoot(t)
	adminHome := filepath.Join(root, "admin-home")
	adminKauket := filepath.Join(adminHome, ".config", "kauket")
	clientHome := filepath.Join(root, "client-home")
	clientKauket := filepath.Join(clientHome, ".config", "kauket")
	bareDir := filepath.Join(root, "bare-remote.git")
	mustMkdir(t, adminHome, 0o700)
	mustMkdir(t, clientHome, 0o700)
	remoteURL := setupBareRemote(t, bareDir)

	res := runKauket(t, bin, adminKauket, adminHome, "init", "--remote", remoteURL, "--recovery-out", filepath.Join(root, "recovery"), "--yes")
	if res.err != nil {
		t.Fatalf("init: %v\nstderr:%s", res.err, res.stderr)
	}
	srcKey := filepath.Join(adminHome, "src", "main_key")
	mustMkdir(t, filepath.Dir(srcKey), 0o700)
	if err := os.WriteFile(srcKey, []byte("SSH KEY"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "add", "ssh.main_private_key", srcKey)
	if res.err != nil {
		t.Fatalf("ssh add: %v\nstderr:%s", res.err, res.stderr)
	}
	res = runKauket(t, bin, clientKauket, clientHome, "request", "ssh", "--remote", remoteURL, "--name", "writer-client", "--yes")
	if res.err != nil {
		t.Fatalf("enroll: %v\nstderr:%s", res.err, res.stderr)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve: %v\nstderr:%s", res.err, res.stderr)
	}

	hostID := readHostID(t, clientKauket)

	srcToken := filepath.Join(adminHome, "src", "token")
	if err := os.WriteFile(srcToken, []byte("NEW V2 TOKEN"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "add", "cloud.vendor.api_token", srcToken, "--dest", "/etc/cloud/token")
	if res.err != nil {
		t.Fatalf("v2 add: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "added cloud.vendor.api_token") {
		t.Fatalf("add output: %q", res.stdout)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "get", "cloud.vendor.api_token", "--stdout")
	if res.err == nil || exitCodeOf(res.err) != 5 {
		t.Fatalf("pre-grant get should exit 5, got %v", res.err)
	}

	res = runKauket(t, bin, adminKauket, adminHome, "grant", hostID, "cloud/vendor")
	if res.err != nil {
		t.Fatalf("grant: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "granted "+hostID) {
		t.Fatalf("grant output: %q", res.stdout)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "get", "cloud.vendor.api_token", "--stdout")
	if res.err != nil {
		t.Fatalf("post-grant get: %v\nstderr:%s", res.err, res.stderr)
	}
	if res.stdout != "NEW V2 TOKEN" {
		t.Fatalf("content: %q", res.stdout)
	}

	res = runKauket(t, bin, adminKauket, adminHome, "revoke", hostID, "cloud/vendor")
	if res.err != nil {
		t.Fatalf("revoke: %v\nstderr:%s", res.err, res.stderr)
	}
	if !strings.Contains(res.stdout, "rotate these secrets") || !strings.Contains(res.stdout, "cloud/vendor/api_token") {
		t.Fatalf("revoke output: %q", res.stdout)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "get", "cloud.vendor.api_token", "--stdout")
	if res.err == nil || exitCodeOf(res.err) != 5 {
		t.Fatalf("post-revoke get should exit 5, got %v; stderr:%s", res.err, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "get", "ssh.main_private_key", "--stdout")
	if res.err != nil || res.stdout != "SSH KEY" {
		t.Fatalf("unrelated grant disturbed: err=%v out=%q", res.err, res.stdout)
	}

	for _, kauketHome := range []string{adminKauket, clientKauket} {
		home := adminHome
		if kauketHome == clientKauket {
			home = clientHome
		}
		res = runKauket(t, bin, kauketHome, home, "verify")
		if res.err != nil {
			t.Fatalf("verify %s: %v\nstderr:%s", kauketHome, res.err, res.stderr)
		}
	}

	adminRepo := filepath.Join(roleHomePath(adminKauket, "admin"), "repo")
	for _, term := range []string{"api_token", "NEW V2 TOKEN", "writer-client", "cloud"} {
		if hits := grepRepo(t, adminRepo, term); len(hits) != 0 {
			t.Fatalf("leak: %q in %v", term, hits)
		}
	}
}
