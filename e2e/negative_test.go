//go:build e2e

package e2e_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNegativeUnapprovedMachineCannotGetSecret(t *testing.T) {
	bin := buildBinary(t)

	root := mustResolvedTempRoot(t)
	adminHome := filepath.Join(root, "admin-home")
	adminKauket := filepath.Join(adminHome, ".config", "kauket")
	clientHome := filepath.Join(root, "machine2-home")
	clientKauket := filepath.Join(clientHome, ".config", "kauket")
	bareDir := filepath.Join(root, "bare-remote.git")

	mustMkdir(t, adminHome, 0o700)
	mustMkdir(t, clientHome, 0o700)
	remoteURL := setupBareRemote(t, bareDir)

	res := runKauket(t, bin, adminKauket, adminHome, "init", "--remote", remoteURL, "--no-github", "--recovery-out", filepath.Join(root, "recovery"), "--yes")
	if res.err != nil {
		t.Fatalf("admin init: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	adminKeyPath := filepath.Join(adminHome, ".ssh", "main_private_key.pem")
	generateEd25519KeyFile(t, adminKeyPath)
	res = runKauket(t, bin, adminKauket, adminHome, "add", "ssh.main_private_key", adminKeyPath)
	if res.err != nil {
		t.Fatalf("admin add: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "enroll", "--remote", remoteURL, "--request", "ssh", "--name", "machine2", "--yes")
	if res.err != nil {
		t.Fatalf("enroll: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "get", "ssh.main_private_key")
	if res.err == nil {
		t.Fatalf("expected get to fail; stdout:%s stderr:%s", res.stdout, res.stderr)
	}
	if code := exitCodeOf(res.err); code != 5 {
		t.Fatalf("expected exit code 5 (ExitNotGranted), got %d; stderr:%s", code, res.stderr)
	}
	if !strings.Contains(res.stderr, "not granted access") {
		t.Fatalf("expected stderr to contain 'not granted access', got: %q", res.stderr)
	}

	dest := filepath.Join(clientHome, ".ssh", "main_private_key")
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no destination file, stat err: %v", err)
	}
}

func TestNegativeExistingUnmanagedFile(t *testing.T) {
	bin := buildBinary(t)

	root := mustResolvedTempRoot(t)
	adminHome := filepath.Join(root, "admin-home")
	adminKauket := filepath.Join(adminHome, ".config", "kauket")
	clientHome := filepath.Join(root, "machine2-home")
	clientKauket := filepath.Join(clientHome, ".config", "kauket")
	bareDir := filepath.Join(root, "bare-remote.git")

	mustMkdir(t, adminHome, 0o700)
	mustMkdir(t, clientHome, 0o700)
	remoteURL := setupBareRemote(t, bareDir)

	res := runKauket(t, bin, adminKauket, adminHome, "init", "--remote", remoteURL, "--no-github", "--recovery-out", filepath.Join(root, "recovery"), "--yes")
	if res.err != nil {
		t.Fatalf("admin init: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	adminKeyPath := filepath.Join(adminHome, ".ssh", "main_private_key.pem")
	generateEd25519KeyFile(t, adminKeyPath)
	res = runKauket(t, bin, adminKauket, adminHome, "add", "ssh.main_private_key", adminKeyPath)
	if res.err != nil {
		t.Fatalf("admin add: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "enroll", "--remote", remoteURL, "--request", "ssh", "--name", "machine2", "--yes")
	if res.err != nil {
		t.Fatalf("enroll: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	sshDir := filepath.Join(clientHome, ".ssh")
	mustMkdir(t, sshDir, 0o700)
	dest := filepath.Join(sshDir, "main_private_key")
	originalContent := []byte("do not overwrite")
	if err := os.WriteFile(dest, originalContent, 0o600); err != nil {
		t.Fatalf("pre-create unmanaged dest: %v", err)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "get", "ssh.main_private_key")
	if res.err == nil {
		t.Fatalf("expected get to fail with unmanaged dest; stdout:%s stderr:%s", res.stdout, res.stderr)
	}
	if code := exitCodeOf(res.err); code != 4 {
		t.Fatalf("expected exit code 4 (ExitInstall), got %d; stderr:%s", code, res.stderr)
	}
	if !strings.Contains(res.stderr, "destination exists and was not installed by kauket") {
		t.Fatalf("expected stderr to contain destination-exists message, got: %q", res.stderr)
	}

	curr, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest after refused install: %v", err)
	}
	if string(curr) != string(originalContent) {
		t.Fatalf("dest content changed after refused install; got %q", string(curr))
	}

	res = runKauket(t, bin, clientKauket, clientHome, "get", "ssh.main_private_key", "--backup")
	if res.err != nil {
		t.Fatalf("get --backup failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	combined := res.stdout + res.stderr
	if !strings.Contains(combined, "creating ~/.ssh/main_private_key") {
		t.Fatalf("expected output to contain 'creating ~/.ssh/main_private_key', got stdout=%q stderr=%q", res.stdout, res.stderr)
	}
	if !strings.Contains(combined, "backup created") {
		t.Fatalf("expected output to contain 'backup created', got stdout=%q stderr=%q", res.stdout, res.stderr)
	}

	entries, err := os.ReadDir(sshDir)
	if err != nil {
		t.Fatalf("read .ssh dir: %v", err)
	}
	var backupPath string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "main_private_key.kauket-bak-") {
			backupPath = filepath.Join(sshDir, name)
			break
		}
	}
	if backupPath == "" {
		t.Fatalf("expected a kauket-bak-* file in %s; entries=%v", sshDir, entries)
	}
	backupBytes, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup file: %v", err)
	}
	if string(backupBytes) != string(originalContent) {
		t.Fatalf("backup content mismatch: want %q, got %q", string(originalContent), string(backupBytes))
	}

	installed, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read installed dest: %v", err)
	}
	adminBytes, err := os.ReadFile(adminKeyPath)
	if err != nil {
		t.Fatalf("read admin key: %v", err)
	}
	if string(installed) != string(adminBytes) {
		t.Fatalf("installed file does not match admin source after backup")
	}
}

func TestNegativeSymlinkDestination(t *testing.T) {
	bin := buildBinary(t)

	root := mustResolvedTempRoot(t)
	adminHome := filepath.Join(root, "admin-home")
	adminKauket := filepath.Join(adminHome, ".config", "kauket")
	clientHome := filepath.Join(root, "machine2-home")
	clientKauket := filepath.Join(clientHome, ".config", "kauket")
	bareDir := filepath.Join(root, "bare-remote.git")

	mustMkdir(t, adminHome, 0o700)
	mustMkdir(t, clientHome, 0o700)
	remoteURL := setupBareRemote(t, bareDir)

	res := runKauket(t, bin, adminKauket, adminHome, "init", "--remote", remoteURL, "--no-github", "--recovery-out", filepath.Join(root, "recovery"), "--yes")
	if res.err != nil {
		t.Fatalf("admin init: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	adminKeyPath := filepath.Join(adminHome, ".ssh", "main_private_key.pem")
	generateEd25519KeyFile(t, adminKeyPath)
	res = runKauket(t, bin, adminKauket, adminHome, "add", "ssh.main_private_key", adminKeyPath)
	if res.err != nil {
		t.Fatalf("admin add: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "enroll", "--remote", remoteURL, "--request", "ssh", "--name", "machine2", "--yes")
	if res.err != nil {
		t.Fatalf("enroll: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	sshDir := filepath.Join(clientHome, ".ssh")
	mustMkdir(t, sshDir, 0o700)
	evilTarget := filepath.Join(root, "evil-target")
	dest := filepath.Join(sshDir, "main_private_key")
	if err := os.Symlink(evilTarget, dest); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "get", "ssh.main_private_key")
	if res.err == nil {
		t.Fatalf("expected get to refuse symlink; stdout:%s stderr:%s", res.stdout, res.stderr)
	}
	if code := exitCodeOf(res.err); code != 4 {
		t.Fatalf("expected exit code 4 (ExitInstall), got %d; stderr:%s", code, res.stderr)
	}
	if !strings.Contains(res.stderr, "refusing to write through symlink") {
		t.Fatalf("expected stderr to contain 'refusing to write through symlink', got: %q", res.stderr)
	}

	if _, err := os.Stat(evilTarget); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected evil target to not exist, stat err: %v", err)
	}

	info, err := os.Lstat(dest)
	if err != nil {
		t.Fatalf("lstat dest: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("dest should still be a symlink, got mode %v", info.Mode())
	}
}

func TestNegativeCorruptObject(t *testing.T) {
	bin := buildBinary(t)

	root := mustResolvedTempRoot(t)
	adminHome := filepath.Join(root, "admin-home")
	adminKauket := filepath.Join(adminHome, ".config", "kauket")
	clientHome := filepath.Join(root, "machine2-home")
	clientKauket := filepath.Join(clientHome, ".config", "kauket")
	bareDir := filepath.Join(root, "bare-remote.git")

	mustMkdir(t, adminHome, 0o700)
	mustMkdir(t, clientHome, 0o700)
	remoteURL := setupBareRemote(t, bareDir)

	res := runKauket(t, bin, adminKauket, adminHome, "init", "--remote", remoteURL, "--no-github", "--recovery-out", filepath.Join(root, "recovery"), "--yes")
	if res.err != nil {
		t.Fatalf("admin init: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	adminKeyPath := filepath.Join(adminHome, ".ssh", "main_private_key.pem")
	generateEd25519KeyFile(t, adminKeyPath)
	res = runKauket(t, bin, adminKauket, adminHome, "add", "ssh.main_private_key", adminKeyPath)
	if res.err != nil {
		t.Fatalf("admin add: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "enroll", "--remote", remoteURL, "--request", "ssh", "--name", "machine2", "--yes")
	if res.err != nil {
		t.Fatalf("enroll: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "get", "ssh.main_private_key")
	if res.err != nil {
		t.Fatalf("initial get to populate client repo failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	dest := filepath.Join(clientHome, ".ssh", "main_private_key")
	if err := os.Remove(dest); err != nil {
		t.Fatalf("remove dest before corrupt test: %v", err)
	}
	clientRoleHome := roleHomePath(clientKauket, "client")
	stateFile := filepath.Join(clientRoleHome, "state", "installed.json")
	if err := os.Remove(stateFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove installed state: %v", err)
	}

	objectsDir := filepath.Join(clientRoleHome, "repo", "objects")
	entries, err := os.ReadDir(objectsDir)
	if err != nil {
		t.Fatalf("read objects dir: %v", err)
	}
	corrupted := false
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "o_") {
			continue
		}
		objPath := filepath.Join(objectsDir, e.Name())
		objBytes, err := os.ReadFile(objPath)
		if err != nil {
			t.Fatalf("read object: %v", err)
		}
		if len(objBytes) < 200 {
			t.Fatalf("object suspiciously short (%d bytes)", len(objBytes))
		}
		objBytes[len(objBytes)-50] ^= 0xFF
		if err := os.WriteFile(objPath, objBytes, 0o600); err != nil {
			t.Fatalf("write corrupt object: %v", err)
		}
		corrupted = true
	}
	if !corrupted {
		t.Fatalf("no secret object found to corrupt; entries: %v", entries)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "get", "ssh.main_private_key", "--no-sync")
	if res.err == nil {
		t.Fatalf("expected get on corrupt object to fail; stdout:%s stderr:%s", res.stdout, res.stderr)
	}
	if code := exitCodeOf(res.err); code != 2 {
		t.Fatalf("expected exit code 2 (ExitCrypto), got %d; stderr:%s", code, res.stderr)
	}
	if !strings.Contains(res.stderr, "decrypt") {
		t.Fatalf("expected stderr to mention decrypt failure, got: %q", res.stderr)
	}
	t.Logf("corrupt object stderr: %q", strings.TrimSpace(res.stderr))

	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected destination not installed, stat err: %v", err)
	}
}
