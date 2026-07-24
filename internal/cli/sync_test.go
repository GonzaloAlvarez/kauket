package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	cryptossh "golang.org/x/crypto/ssh"
)

func TestSyncAdminAfterInit(t *testing.T) {
	a, fake, _ := newTestApp(t)
	remoteURL := bareRepo(t)
	flags := &initFlags{
		owner:    "GonzaloAlvarez",
		repo:     "kauket-store",
		private:  true,
		remote:   remoteURL,
		noGitHub: true,
		yes:      true,
	}
	if err := runInit(context.Background(), a, flags); err != nil {
		t.Fatalf("init: %v", err)
	}
	fake.Lines = nil
	if err := runSync(context.Background(), a); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(fake.Lines) != 1 || fake.Lines[0] != "synced" {
		t.Fatalf("want 'synced', got %v", fake.Lines)
	}
}

func TestClientSyncUsesSSHDeployKeyTransport(t *testing.T) {
	home := t.TempDir()
	keyPath := filepath.Join(home, "git", "deploy_key")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeEd25519DeployKey(t, keyPath)

	cfg := &config.Client{
		Repo: config.RepoInfo{
			RemoteHTTPS: "https://github.com/acme/store.git",
			RemoteSSH:   "git@github.com:acme/store.git",
		},
		Host: config.HostInfo{DeployKeyPath: filepath.Join("git", "deploy_key")},
	}

	remoteURL := selectClientRemote(cfg)
	if remoteURL != cfg.Repo.RemoteSSH {
		t.Fatalf("want SSH remote %q, got %q", cfg.Repo.RemoteSSH, remoteURL)
	}

	tr, err := buildGetTransport(home, cfg, remoteURL)
	if err != nil {
		t.Fatalf("buildGetTransport: %v", err)
	}
	if _, ok := tr.(*gitstore.SSHDeployKeyTransport); !ok {
		t.Fatalf("want *SSHDeployKeyTransport for SSH remote, got %T", tr)
	}
	if tr.Auth() == nil {
		t.Fatal("SSH transport must supply non-nil auth (avoids go-git SSH agent fallback)")
	}
}

func writeEd25519DeployKey(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	block, err := cryptossh.MarshalPrivateKey(priv, "kauket-test")
	if err != nil {
		t.Fatalf("marshal ed25519: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func TestSyncUninitializedFails(t *testing.T) {
	a, _, _ := newTestApp(t)
	err := runSync(context.Background(), a)
	if err == nil {
		t.Fatalf("expected error on uninitialized sync")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %d", exitErr.Code)
	}
}
