//go:build e2e

package e2e_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func legacyizeE2E(t *testing.T, base, role string) {
	t.Helper()
	roleHome := filepath.Join(base, role)
	entries, err := os.ReadDir(roleHome)
	if err != nil {
		t.Fatalf("read role home: %v", err)
	}
	for _, e := range entries {
		if err := os.Rename(filepath.Join(roleHome, e.Name()), filepath.Join(base, e.Name())); err != nil {
			t.Fatalf("move %s: %v", e.Name(), err)
		}
	}
	if err := os.Remove(roleHome); err != nil {
		t.Fatalf("remove role home: %v", err)
	}
}

func TestMigrateLocalE2E(t *testing.T) {
	bin := buildBinary(t)

	root := mustResolvedTempRoot(t)
	home := filepath.Join(root, "admin-home")
	kauketHome := filepath.Join(home, ".config", "kauket")
	bareDir := filepath.Join(root, "bare-remote.git")
	mustMkdir(t, home, 0o700)
	remoteURL := setupBareRemote(t, bareDir)

	res := runKauket(t, bin, kauketHome, home, "init", "--remote", remoteURL, "--no-github", "--yes")
	if res.err != nil {
		t.Fatalf("init: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	legacyizeE2E(t, kauketHome, "admin")

	res = runKauket(t, bin, kauketHome, home, "status")
	if res.err != nil {
		t.Fatalf("status on legacy layout: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "role: admin") {
		t.Fatalf("legacy status should report admin, got: %q", res.stdout)
	}

	srcKey := filepath.Join(home, "src", "main_private_key.pem")
	generateEd25519KeyFile(t, srcKey)
	res = runKauket(t, bin, kauketHome, home, "add", "ssh.main_private_key", srcKey)
	if res.err != nil {
		t.Fatalf("add on legacy layout: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, kauketHome, home, "migrate")
	if res.err != nil {
		t.Fatalf("migrate: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "migrated admin role to ") {
		t.Fatalf("migrate output: %q", res.stdout)
	}

	for _, p := range []string{
		filepath.Join(kauketHome, "admin", "config.json"),
		filepath.Join(kauketHome, "admin", "identities", "admin.txt"),
		filepath.Join(kauketHome, "admin", "repo", "repo.json"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s after migrate: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(kauketHome, "config.json")); !os.IsNotExist(err) {
		t.Fatalf("root config.json should be gone after migrate, stat err: %v", err)
	}

	res = runKauket(t, bin, kauketHome, home, "migrate")
	if res.err != nil {
		t.Fatalf("second migrate: %v\nstderr:%s", res.err, res.stderr)
	}
	if !strings.Contains(res.stdout, "nothing to migrate") {
		t.Fatalf("second migrate output: %q", res.stdout)
	}

	res = runKauket(t, bin, kauketHome, home, "list")
	if res.err != nil {
		t.Fatalf("list after migrate: %v\nstderr:%s", res.err, res.stderr)
	}
	if !strings.Contains(res.stdout, "ssh.main_private_key") {
		t.Fatalf("list after migrate missing secret, got: %q", res.stdout)
	}
}

func TestConsolidateTwoHomesE2E(t *testing.T) {
	bin := buildBinary(t)

	root := mustResolvedTempRoot(t)
	adminHome := filepath.Join(root, "admin-home")
	adminKauket := filepath.Join(adminHome, ".config", "kauket")
	clientHome := filepath.Join(root, "client-home")
	clientKauket := filepath.Join(clientHome, ".config", "kauket")
	bareDir := filepath.Join(root, "bare-remote.git")
	mustMkdir(t, adminHome, 0o700)
	mustMkdir(t, clientHome, 0o700)
	remoteURL := setupBareRemote(t, bareDir)

	res := runKauket(t, bin, adminKauket, adminHome, "init", "--remote", remoteURL, "--no-github", "--yes")
	if res.err != nil {
		t.Fatalf("init: %v\nstderr:%s", res.err, res.stderr)
	}
	srcKey := filepath.Join(adminHome, "src", "main_private_key.pem")
	generateEd25519KeyFile(t, srcKey)
	res = runKauket(t, bin, adminKauket, adminHome, "add", "ssh.main_private_key", srcKey)
	if res.err != nil {
		t.Fatalf("add: %v\nstderr:%s", res.err, res.stderr)
	}
	res = runKauket(t, bin, clientKauket, clientHome, "enroll", "--remote", remoteURL, "--request", "ssh", "--name", "machine2", "--yes")
	if res.err != nil {
		t.Fatalf("enroll: %v\nstderr:%s", res.err, res.stderr)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve: %v\nstderr:%s", res.err, res.stderr)
	}

	if err := os.Rename(filepath.Join(clientKauket, "client"), filepath.Join(adminKauket, "client")); err != nil {
		t.Fatalf("consolidate move: %v", err)
	}

	res = runKauket(t, bin, adminKauket, adminHome, "status")
	if res.err != nil {
		t.Fatalf("status after consolidation: %v\nstderr:%s", res.err, res.stderr)
	}
	if !strings.Contains(res.stdout, "role: admin") || !strings.Contains(res.stdout, "role: client") {
		t.Fatalf("status should show both roles, got: %q", res.stdout)
	}

	res = runKauket(t, bin, adminKauket, adminHome, "get", "ssh.main_private_key")
	if res.err != nil {
		t.Fatalf("get after consolidation: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if _, err := os.Stat(filepath.Join(adminHome, ".ssh", "main_private_key")); err != nil {
		t.Fatalf("installed key missing after consolidation: %v", err)
	}
}
