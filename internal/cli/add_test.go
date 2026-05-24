package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	"github.com/gonzaloalvarez/kauket/internal/model"
	"github.com/gonzaloalvarez/kauket/internal/ui"
)

func initAdminFixture(t *testing.T) (*app.App, *ui.Fake, string) {
	t.Helper()
	a, fake, home := newTestApp(t)
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
	return a, fake, home
}

func loadAdminVault(t *testing.T, home string) model.Vault {
	t.Helper()
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		t.Fatalf("load admin: %v", err)
	}
	vaultPath := filepath.Join(config.RepoDir(home), "admin", "vault.age")
	ct, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read vault: %v", err)
	}
	idPath := cfg.Admin.IdentityPath
	if !filepath.IsAbs(idPath) {
		idPath = filepath.Join(home, idPath)
	}
	v, err := bundle.DecodeVault(ct, agebox.FileIdentityProvider{Path: idPath})
	if err != nil {
		t.Fatalf("decode vault: %v", err)
	}
	return v
}

func writeAdminVault(t *testing.T, home string, v model.Vault) {
	t.Helper()
	recips := make([]string, 0, len(v.Admins))
	for _, a := range v.Admins {
		recips = append(recips, a.Recipient)
	}
	ct, err := bundle.EncodeVault(v, agebox.X25519RecipientProvider{Strings: recips})
	if err != nil {
		t.Fatalf("encode vault: %v", err)
	}
	vaultPath := filepath.Join(config.RepoDir(home), "admin", "vault.age")
	if err := os.WriteFile(vaultPath, ct, 0o600); err != nil {
		t.Fatalf("write vault: %v", err)
	}
	commitAdminChanges(t, home)
}

func commitAdminChanges(t *testing.T, home string) {
	t.Helper()
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		t.Fatalf("load admin: %v", err)
	}
	store, err := gitstore.OpenOrClone(context.Background(), gitstore.Config{
		RepoPath: config.RepoDir(home),
		URL:      cfg.Repo.RemoteHTTPS,
		LockPath: config.LockPath(home),
	}, gitstore.FileURLTransport{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	author := gitstore.Author{Name: cfg.CommitAuthor.Name, Email: cfg.CommitAuthor.Email}
	if err := store.CommitAndPush(context.Background(), "kauket: update vault", author); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func addHostGrant(t *testing.T, home, hostID, displayName string, profiles, secrets []string) (*age.X25519Identity, string) {
	t.Helper()
	hostIdentity, err := agebox.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate host identity: %v", err)
	}
	hostIdentityPath := filepath.Join(home, "identities", "host_"+hostID+".txt")
	if err := os.MkdirAll(filepath.Dir(hostIdentityPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(hostIdentityPath, []byte(hostIdentity.String()+"\n"), 0o600); err != nil {
		t.Fatalf("write host id: %v", err)
	}
	v := loadAdminVault(t, home)
	if v.Hosts == nil {
		v.Hosts = map[string]model.Host{}
	}
	v.Hosts[hostID] = model.Host{
		DisplayName:          displayName,
		ReportedHostname:     displayName,
		AgeRecipient:         hostIdentity.Recipient().String(),
		DeployKeyFingerprint: "SHA256:test",
		GrantedProfiles:      profiles,
		GrantedSecrets:       secrets,
		CreatedAt:            v.UpdatedAt,
		ApprovedAt:           v.UpdatedAt,
	}
	writeAdminVault(t, home, v)
	return hostIdentity, hostIdentityPath
}

func writeSSHKeyFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "main_private_key.pem")
	body := "-----BEGIN OPENSSH PRIVATE KEY-----\nKAUKETTESTFAKEKEYDATA1234567890abcdefABCDEFghIJKL=\n-----END OPENSSH PRIVATE KEY-----\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestAddSshSecretRebuildsBundlesForGrantedHost(t *testing.T) {
	a, fake, home := initAdminFixture(t)
	hostID := "h_aaaaaaaaaaaaaaaa"
	hostIdentity, hostIdentityPath := addHostGrant(t, home, hostID, "test-host", []string{"ssh"}, nil)
	_ = hostIdentity

	keyPath := writeSSHKeyFixture(t)
	if err := runAdd(context.Background(), a, &addFlags{}, "ssh.main_private_key", keyPath); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	if len(fake.Lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(fake.Lines), fake.Lines)
	}
	if fake.Lines[0] != "added ssh.main_private_key" {
		t.Fatalf("line 0: %q", fake.Lines[0])
	}
	if fake.Lines[1] != "updated 1 host bundles" {
		t.Fatalf("line 1: %q", fake.Lines[1])
	}

	v := loadAdminVault(t, home)
	secret, ok := v.Secrets["ssh.main_private_key"]
	if !ok {
		t.Fatalf("secret missing from vault")
	}
	if secret.Install.Destination != "~/.ssh/main_private_key" {
		t.Fatalf("dest: %q", secret.Install.Destination)
	}
	if len(secret.Profiles) != 1 || secret.Profiles[0] != "ssh" {
		t.Fatalf("profiles: %v", secret.Profiles)
	}
	if secret.SHA256 == "" {
		t.Fatalf("sha256 empty")
	}

	bundlePath := filepath.Join(config.RepoDir(home), "bundles", hostID+".age")
	ct, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	hostBundle, err := bundle.DecodeHostBundle(ct, agebox.FileIdentityProvider{Path: hostIdentityPath})
	if err != nil {
		t.Fatalf("decode bundle with host id: %v", err)
	}
	if _, ok := hostBundle.Secrets["ssh.main_private_key"]; !ok {
		t.Fatalf("bundle missing secret")
	}

	adminIDPath := config.AdminIdentityPath(home)
	if _, err := bundle.DecodeHostBundle(ct, agebox.FileIdentityProvider{Path: adminIDPath}); err != nil {
		t.Fatalf("admin recovery decode failed: %v", err)
	}

	vaultPath := filepath.Join(config.RepoDir(home), "admin", "vault.age")
	vaultCT, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read vault ct: %v", err)
	}
	if bytes.Contains(vaultCT, []byte("ssh.main_private_key")) {
		t.Fatalf("vault ciphertext leaks secret id")
	}
	if bytes.Contains(ct, []byte("ssh.main_private_key")) {
		t.Fatalf("bundle ciphertext leaks secret id")
	}
}

func TestAddRejectsInvalidSecretID(t *testing.T) {
	a, _, _ := initAdminFixture(t)
	keyPath := writeSSHKeyFixture(t)
	err := runAdd(context.Background(), a, &addFlags{}, "SSH.main_private_key", keyPath)
	if err == nil {
		t.Fatalf("expected error for invalid id")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %d", exitErr.Code)
	}
}

func TestAddRejectsExistingWithoutForce(t *testing.T) {
	a, fake, _ := initAdminFixture(t)
	keyPath := writeSSHKeyFixture(t)
	if err := runAdd(context.Background(), a, &addFlags{}, "ssh.main_private_key", keyPath); err != nil {
		t.Fatalf("first add: %v", err)
	}
	fake.Lines = nil
	err := runAdd(context.Background(), a, &addFlags{}, "ssh.main_private_key", keyPath)
	if err == nil {
		t.Fatalf("expected error on duplicate add")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %d", exitErr.Code)
	}
	if !strings.Contains(err.Error(), "force") {
		t.Fatalf("expected --force hint, got %q", err.Error())
	}

	fake.Lines = nil
	if err := runAdd(context.Background(), a, &addFlags{force: true}, "ssh.main_private_key", keyPath); err != nil {
		t.Fatalf("force add: %v", err)
	}
	if len(fake.Lines) != 2 || fake.Lines[0] != "updated ssh.main_private_key" {
		t.Fatalf("expected updated line, got %v", fake.Lines)
	}
}

func TestAddRequiresDestWhenInferenceFails(t *testing.T) {
	a, fake, _ := initAdminFixture(t)
	keyPath := writeSSHKeyFixture(t)
	err := runAdd(context.Background(), a, &addFlags{}, "foo.bar", keyPath)
	if err == nil {
		t.Fatalf("expected error without --dest")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %d", exitErr.Code)
	}
	if !strings.Contains(err.Error(), "no destination rule") || !strings.Contains(err.Error(), "--dest") {
		t.Fatalf("expected message about destination rule, got %q", err.Error())
	}

	fake.Lines = nil
	if err := runAdd(context.Background(), a, &addFlags{dest: "/etc/foo/bar"}, "foo.bar", keyPath); err != nil {
		t.Fatalf("add with --dest: %v", err)
	}
}

func TestAddRejectsOversizedSource(t *testing.T) {
	a, _, _ := initAdminFixture(t)
	keyPath := filepath.Join(t.TempDir(), "big.bin")
	data := bytes.Repeat([]byte("a"), 8)
	if err := os.WriteFile(keyPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := runAdd(context.Background(), a, &addFlags{maxSize: 4}, "ssh.main_private_key", keyPath)
	if err == nil {
		t.Fatalf("expected oversize error")
	}
	if !strings.Contains(err.Error(), "max size") {
		t.Fatalf("expected max size mention, got %q", err.Error())
	}
}
