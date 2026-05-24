package gitstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/skeema/knownhosts"
	cryptossh "golang.org/x/crypto/ssh"
)

func writeEd25519KeyFile(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	block, err := cryptossh.MarshalPrivateKey(priv, "kauket-test")
	if err != nil {
		t.Fatalf("marshal ed25519: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func writeRSAKeyFile(t *testing.T, path string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	block, err := cryptossh.MarshalPrivateKey(priv, "kauket-test-rsa")
	if err != nil {
		t.Fatalf("marshal rsa: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write rsa key: %v", err)
	}
}

func TestNewSSHDeployKeyTransportEd25519Success(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "deploy_key")
	writeEd25519KeyFile(t, keyPath)

	tr, err := NewSSHDeployKeyTransport(keyPath)
	if err != nil {
		t.Fatalf("NewSSHDeployKeyTransport: %v", err)
	}
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
	if tr.signer == nil {
		t.Fatal("expected non-nil signer")
	}
	if tr.knownHosts == nil {
		t.Fatal("expected non-nil knownHosts callback")
	}
	if tr.signer.PublicKey().Type() != cryptossh.KeyAlgoED25519 {
		t.Fatalf("expected ed25519 signer, got %s", tr.signer.PublicKey().Type())
	}
}

func TestSSHDeployKeyTransportAuthReturnsPublicKeys(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "deploy_key")
	writeEd25519KeyFile(t, keyPath)

	tr, err := NewSSHDeployKeyTransport(keyPath)
	if err != nil {
		t.Fatalf("NewSSHDeployKeyTransport: %v", err)
	}
	auth := tr.Auth()
	if auth == nil {
		t.Fatal("expected non-nil auth")
	}
	pk, ok := auth.(*ssh.PublicKeys)
	if !ok {
		t.Fatalf("expected *ssh.PublicKeys, got %T", auth)
	}
	if pk.User != "git" {
		t.Fatalf("expected user git, got %q", pk.User)
	}
	if pk.Signer == nil {
		t.Fatal("expected non-nil Signer in PublicKeys")
	}
	if pk.HostKeyCallback == nil {
		t.Fatal("expected non-nil HostKeyCallback in PublicKeys")
	}
}

func TestNewSSHDeployKeyTransportRejectsRSA(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "rsa_key")
	writeRSAKeyFile(t, keyPath)

	_, err := NewSSHDeployKeyTransport(keyPath)
	if err == nil {
		t.Fatal("expected error for rsa key, got nil")
	}
	if !strings.Contains(err.Error(), "ed25519") {
		t.Fatalf("expected error mentioning ed25519, got %v", err)
	}
}

func TestNewSSHDeployKeyTransportNonexistentFile(t *testing.T) {
	_, err := NewSSHDeployKeyTransport(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestNewSSHDeployKeyTransportEmptyPath(t *testing.T) {
	_, err := NewSSHDeployKeyTransport("")
	if err == nil {
		t.Fatal("expected error for empty path, got nil")
	}
}

func TestNewSSHDeployKeyTransportGarbageFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "garbage")
	if err := os.WriteFile(keyPath, []byte("this is not a key\n"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	_, err := NewSSHDeployKeyTransport(keyPath)
	if err == nil {
		t.Fatal("expected error for garbage file, got nil")
	}
}

func TestNewSSHDeployKeyTransportRejectsWrongMode(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "deploy_key")
	writeEd25519KeyFile(t, keyPath)
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err := NewSSHDeployKeyTransport(keyPath)
	if err == nil {
		t.Fatal("expected error for non-0600 mode, got nil")
	}
	if !strings.Contains(err.Error(), "0600") {
		t.Fatalf("expected error mentioning 0600, got %v", err)
	}
}

func TestKnownHostsEmbeddedContent(t *testing.T) {
	if len(githubKnownHostsBytes) == 0 {
		t.Fatal("expected non-empty embedded known_hosts")
	}
	if !strings.Contains(string(githubKnownHostsBytes), "ssh-ed25519") {
		t.Fatal("expected ssh-ed25519 line in embedded known_hosts")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(path, githubKnownHostsBytes, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	hkcb, err := knownhosts.New(path)
	if err != nil {
		t.Fatalf("knownhosts.New: %v", err)
	}
	if hkcb.HostKeyCallback() == nil {
		t.Fatal("expected non-nil HostKeyCallback")
	}
}

func TestEmbeddedKnownHostsLoadsAfterTempFileRemoved(t *testing.T) {
	before, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("read tempdir: %v", err)
	}
	cb, err := loadEmbeddedKnownHosts()
	if err != nil {
		t.Fatalf("loadEmbeddedKnownHosts: %v", err)
	}
	if cb == nil {
		t.Fatal("expected non-nil callback")
	}
	after, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("read tempdir after: %v", err)
	}
	for _, e := range after {
		if !strings.HasPrefix(e.Name(), "kauket-known-hosts-") {
			continue
		}
		seen := false
		for _, b := range before {
			if b.Name() == e.Name() {
				seen = true
				break
			}
		}
		if !seen {
			t.Fatalf("temp known_hosts file %q was not cleaned up", e.Name())
		}
	}
}

func TestSelectTransportWithSSHGitAtURL(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "deploy_key")
	writeEd25519KeyFile(t, keyPath)

	tr, err := SelectTransportWithSSH("git@github.com:org/repo.git", "", keyPath)
	if err != nil {
		t.Fatalf("SelectTransportWithSSH: %v", err)
	}
	if _, ok := tr.(*SSHDeployKeyTransport); !ok {
		t.Fatalf("expected *SSHDeployKeyTransport, got %T", tr)
	}
}

func TestSelectTransportWithSSHSchemeURL(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "deploy_key")
	writeEd25519KeyFile(t, keyPath)

	tr, err := SelectTransportWithSSH("ssh://git@github.com/org/repo.git", "", keyPath)
	if err != nil {
		t.Fatalf("SelectTransportWithSSH: %v", err)
	}
	if _, ok := tr.(*SSHDeployKeyTransport); !ok {
		t.Fatalf("expected *SSHDeployKeyTransport, got %T", tr)
	}
}

func TestSelectTransportWithSSHHTTPSURL(t *testing.T) {
	tr, err := SelectTransportWithSSH("https://github.com/org/repo.git", "ghs_abc", "")
	if err != nil {
		t.Fatalf("SelectTransportWithSSH: %v", err)
	}
	hp, ok := tr.(HTTPSTokenTransport)
	if !ok {
		t.Fatalf("expected HTTPSTokenTransport, got %T", tr)
	}
	if hp.Token != "ghs_abc" {
		t.Fatalf("expected token ghs_abc, got %q", hp.Token)
	}
}

func TestSelectTransportWithSSHFileURL(t *testing.T) {
	tr, err := SelectTransportWithSSH("file:///tmp/foo.git", "", "")
	if err != nil {
		t.Fatalf("SelectTransportWithSSH: %v", err)
	}
	if _, ok := tr.(FileURLTransport); !ok {
		t.Fatalf("expected FileURLTransport, got %T", tr)
	}
}
