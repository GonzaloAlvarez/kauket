//go:build e2e

package e2e_test

import (
	"bytes"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRealDataSshEd25519PrivateKey(t *testing.T) {
	sshKeygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not available; skipping real-data ssh test")
	}

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

	res := runKauket(t, bin, adminKauket, adminHome, "init", "--remote", remoteURL, "--no-github", "--yes")
	if res.err != nil {
		t.Fatalf("admin init: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	keyDir := filepath.Join(adminHome, ".ssh")
	mustMkdir(t, keyDir, 0o700)
	adminKeyPath := filepath.Join(keyDir, "main_private_key.pem")
	out, err := exec.Command(sshKeygen, "-t", "ed25519", "-N", "", "-f", adminKeyPath, "-q").CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, string(out))
	}

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
		t.Fatalf("get: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	clientKeyPath := filepath.Join(clientHome, ".ssh", "main_private_key")
	pubOut, err := exec.Command(sshKeygen, "-y", "-f", clientKeyPath).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -y on installed key: %v\n%s", err, string(pubOut))
	}
	if !strings.HasPrefix(strings.TrimSpace(string(pubOut)), "ssh-ed25519 ") {
		t.Fatalf("expected ed25519 public key from ssh-keygen, got: %q", string(pubOut))
	}

	adminBytes, err := os.ReadFile(adminKeyPath)
	if err != nil {
		t.Fatalf("read admin key: %v", err)
	}
	clientBytes, err := os.ReadFile(clientKeyPath)
	if err != nil {
		t.Fatalf("read client key: %v", err)
	}
	if !bytes.Equal(adminBytes, clientBytes) {
		t.Fatalf("installed file does not match source byte-for-byte")
	}

	adminRepo := filepath.Join(adminKauket, "repo")
	for _, term := range []string{"ssh.main_private_key", "main_private_key", "BEGIN OPENSSH"} {
		hits := grepRepo(t, adminRepo, term)
		if len(hits) != 0 {
			t.Fatalf("leak: term %q found in admin repo: %v", term, hits)
		}
	}
}

func TestRealDataAwsCredentialsFile(t *testing.T) {
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

	res := runKauket(t, bin, adminKauket, adminHome, "init", "--remote", remoteURL, "--no-github", "--yes")
	if res.err != nil {
		t.Fatalf("admin init: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	awsSrc := filepath.Join(adminHome, "aws_credentials")
	awsContent := "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	if err := os.WriteFile(awsSrc, []byte(awsContent), 0o600); err != nil {
		t.Fatalf("write aws creds source: %v", err)
	}

	res = runKauket(t, bin, adminKauket, adminHome, "add", "aws.primary_account.key_file", awsSrc, "--dest", "~/.aws/credentials", "--profile", "aws")
	if res.err != nil {
		t.Fatalf("admin add aws: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "enroll", "--remote", remoteURL, "--request", "aws", "--name", "machine2", "--yes")
	if res.err != nil {
		t.Fatalf("enroll: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	res = runKauket(t, bin, clientKauket, clientHome, "get", "aws.primary_account.key_file")
	if res.err != nil {
		t.Fatalf("get aws: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	installedPath := filepath.Join(clientHome, ".aws", "credentials")
	installed, err := os.ReadFile(installedPath)
	if err != nil {
		t.Fatalf("read installed aws creds: %v", err)
	}
	if !bytes.Contains(installed, []byte("aws_access_key_id")) {
		t.Fatalf("installed aws creds missing aws_access_key_id: %s", string(installed))
	}
	if !bytes.Equal(installed, []byte(awsContent)) {
		t.Fatalf("installed aws creds differ from source; got %q", string(installed))
	}

	adminRepo := filepath.Join(adminKauket, "repo")
	for _, term := range []string{"AKIAIOSFODNN7EXAMPLE", "aws.primary_account"} {
		hits := grepRepo(t, adminRepo, term)
		if len(hits) != 0 {
			t.Fatalf("leak: term %q found in admin repo: %v", term, hits)
		}
	}
}

func TestRealDataBinaryFile(t *testing.T) {
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

	res := runKauket(t, bin, adminKauket, adminHome, "init", "--remote", remoteURL, "--no-github", "--yes")
	if res.err != nil {
		t.Fatalf("admin init: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	blob := make([]byte, 32*1024)
	if _, err := rand.Read(blob); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	blobPath := filepath.Join(adminHome, "blob.bin")
	if err := os.WriteFile(blobPath, blob, 0o600); err != nil {
		t.Fatalf("write blob: %v", err)
	}

	res = runKauket(t, bin, adminKauket, adminHome, "add", "binary.test_blob", blobPath, "--dest", "~/.local/share/test_blob", "--profile", "test")
	if res.err != nil {
		t.Fatalf("admin add binary: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "enroll", "--remote", remoteURL, "--request", "test", "--name", "machine2", "--yes")
	if res.err != nil {
		t.Fatalf("enroll: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	res = runKauket(t, bin, clientKauket, clientHome, "get", "binary.test_blob")
	if res.err != nil {
		t.Fatalf("get binary: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	installedPath := filepath.Join(clientHome, ".local", "share", "test_blob")
	installed, err := os.ReadFile(installedPath)
	if err != nil {
		t.Fatalf("read installed blob: %v", err)
	}
	if !bytes.Equal(installed, blob) {
		t.Fatalf("installed blob differs from source: lens src=%d installed=%d", len(blob), len(installed))
	}
}
