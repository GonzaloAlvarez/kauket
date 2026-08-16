package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	"github.com/gonzaloalvarez/kauket/internal/ui"
	cryptossh "golang.org/x/crypto/ssh"
)

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

func breakStoreRemote(t *testing.T, home string) {
	t.Helper()
	repo, err := gogit.PlainOpen(config.RepoDir(home))
	if err != nil {
		t.Fatalf("open clone: %v", err)
	}
	rem, err := repo.Remote("origin")
	if err != nil {
		t.Fatalf("origin remote: %v", err)
	}
	url := rem.Config().URLs[0]
	path := strings.TrimPrefix(url, "file://")
	if err := os.Rename(path, path+".gone"); err != nil {
		t.Fatalf("rename bare repo: %v", err)
	}
}

func TestSyncForReadDegradesToLocal(t *testing.T) {
	base, _, _ := setupAdminStore(t)
	fake := &ui.Fake{}
	a := &app.App{UI: fake, Home: base}

	breakStoreRemote(t, config.RoleHome(base, config.RoleAdmin))

	if err := runList(context.Background(), a, ""); err != nil {
		t.Fatalf("list with broken remote should degrade to local copy: %v", err)
	}
	found := false
	for _, e := range fake.Errors {
		if strings.Contains(e, "using local store copy") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected sync-failure warning, got errors: %v", fake.Errors)
	}
}

func TestSyncForReadFailsWithoutLocalClone(t *testing.T) {
	base := t.TempDir()
	a := &app.App{UI: &ui.Fake{}, Home: base}
	home := config.RoleHome(base, config.RoleClient)
	clientCfg := &config.Client{
		Schema:  config.ConfigSchema,
		Role:    config.RoleClient,
		StoreID: "ks_test",
		Host: config.HostInfo{
			ID:            "h_test",
			IdentityPath:  filepath.Join("identities", "host.txt"),
			DeployKeyPath: filepath.Join("git", "deploy_key"),
		},
		Repo: config.RepoInfo{RemoteHTTPS: "file:///nonexistent-kauket-remote"},
	}
	if err := config.SaveClient(home, clientCfg); err != nil {
		t.Fatalf("save client: %v", err)
	}

	err := runList(context.Background(), a, "")
	if err == nil {
		t.Fatalf("expected error when remote unreachable and no local clone exists")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitSync {
		t.Fatalf("expected ExitSync, got %v", err)
	}
}
