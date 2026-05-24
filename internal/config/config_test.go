package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func adminFixture() *Admin {
	return &Admin{
		Schema:  ConfigSchema,
		Role:    RoleAdmin,
		StoreID: "ks_6me7bk1f9s4xz2qa",
		Repo:    DefaultRepoInfo("GonzaloAlvarez", "kauket-store"),
		Admin: AdminInfo{
			RecipientID:  "ar_3m0vq2ks9p8n1c7x",
			IdentityPath: "identities/admin.txt",
		},
		CommitAuthor: CommitAuthor{
			Name:  "kauket",
			Email: "kauket@localhost",
		},
	}
}

func clientFixture() *Client {
	return &Client{
		Schema:  ConfigSchema,
		Role:    RoleClient,
		StoreID: "ks_6me7bk1f9s4xz2qa",
		Host: HostInfo{
			ID:            "h_7j4v6m2q9xk3p8da",
			DisplayName:   "machine2",
			IdentityPath:  "identities/host.txt",
			DeployKeyPath: "git/deploy_key",
		},
		Repo: DefaultRepoInfo("GonzaloAlvarez", "kauket-store"),
		CommitAuthor: CommitAuthor{
			Name:  "kauket",
			Email: "kauket@localhost",
		},
	}
}

func setupHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "kauket")
	t.Setenv("KAUKET_HOME", home)
	if _, err := EnsureHome(); err != nil {
		t.Fatalf("EnsureHome: %v", err)
	}
	return home
}

func TestDefaultRepoInfo(t *testing.T) {
	r := DefaultRepoInfo("GonzaloAlvarez", "kauket-store")
	if r.Owner != "GonzaloAlvarez" {
		t.Errorf("Owner = %q", r.Owner)
	}
	if r.Name != "kauket-store" {
		t.Errorf("Name = %q", r.Name)
	}
	if r.RemoteHTTPS != "https://github.com/GonzaloAlvarez/kauket-store.git" {
		t.Errorf("RemoteHTTPS = %q", r.RemoteHTTPS)
	}
	if r.RemoteSSH != "git@github.com:GonzaloAlvarez/kauket-store.git" {
		t.Errorf("RemoteSSH = %q", r.RemoteSSH)
	}
	if r.DefaultBranch != "main" {
		t.Errorf("DefaultBranch = %q", r.DefaultBranch)
	}
}

func TestSaveAdmin_RoundTrip(t *testing.T) {
	home := setupHome(t)
	in := adminFixture()
	if err := SaveAdmin(home, in); err != nil {
		t.Fatalf("SaveAdmin: %v", err)
	}
	out, err := LoadAdmin(home)
	if err != nil {
		t.Fatalf("LoadAdmin: %v", err)
	}
	if out.Schema != in.Schema || out.Role != in.Role || out.StoreID != in.StoreID {
		t.Fatalf("admin schema/role/store mismatch: got %+v", out)
	}
	if out.Repo != in.Repo {
		t.Fatalf("repo mismatch: got %+v want %+v", out.Repo, in.Repo)
	}
	if out.Admin != in.Admin {
		t.Fatalf("admin info mismatch: got %+v want %+v", out.Admin, in.Admin)
	}
	if out.CommitAuthor != in.CommitAuthor {
		t.Fatalf("commit author mismatch: got %+v want %+v", out.CommitAuthor, in.CommitAuthor)
	}
}

func TestSaveAdmin_WritesMode0600(t *testing.T) {
	home := setupHome(t)
	if err := SaveAdmin(home, adminFixture()); err != nil {
		t.Fatalf("SaveAdmin: %v", err)
	}
	info, err := os.Stat(ConfigPath(home))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("config.json mode = %o, want 0600", mode)
	}
}

func TestSaveClient_RoundTrip(t *testing.T) {
	home := setupHome(t)
	in := clientFixture()
	if err := SaveClient(home, in); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	out, err := LoadClient(home)
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if out.Schema != in.Schema || out.Role != in.Role || out.StoreID != in.StoreID {
		t.Fatalf("client schema/role/store mismatch: got %+v", out)
	}
	if out.Host != in.Host {
		t.Fatalf("host mismatch: got %+v want %+v", out.Host, in.Host)
	}
	if out.Repo != in.Repo {
		t.Fatalf("repo mismatch: got %+v want %+v", out.Repo, in.Repo)
	}
	if out.CommitAuthor != in.CommitAuthor {
		t.Fatalf("commit author mismatch: got %+v want %+v", out.CommitAuthor, in.CommitAuthor)
	}
}

func TestSaveClient_WritesMode0600(t *testing.T) {
	home := setupHome(t)
	if err := SaveClient(home, clientFixture()); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	info, err := os.Stat(ConfigPath(home))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("config.json mode = %o, want 0600", mode)
	}
}

func TestLoadAdmin_ClientConfigReturnsNotAdmin(t *testing.T) {
	home := setupHome(t)
	if err := SaveClient(home, clientFixture()); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	if _, err := LoadAdmin(home); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("LoadAdmin on client = %v, want ErrNotAdmin", err)
	}
}

func TestLoadClient_AdminConfigReturnsNotClient(t *testing.T) {
	home := setupHome(t)
	if err := SaveAdmin(home, adminFixture()); err != nil {
		t.Fatalf("SaveAdmin: %v", err)
	}
	if _, err := LoadClient(home); !errors.Is(err, ErrNotClient) {
		t.Fatalf("LoadClient on admin = %v, want ErrNotClient", err)
	}
}

func TestLoadAdmin_MissingFile(t *testing.T) {
	home := setupHome(t)
	if _, err := LoadAdmin(home); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("LoadAdmin on missing = %v, want ErrNoConfig", err)
	}
}

func TestLoadClient_MissingFile(t *testing.T) {
	home := setupHome(t)
	if _, err := LoadClient(home); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("LoadClient on missing = %v, want ErrNoConfig", err)
	}
}

func TestPeekRole_Admin(t *testing.T) {
	home := setupHome(t)
	if err := SaveAdmin(home, adminFixture()); err != nil {
		t.Fatalf("SaveAdmin: %v", err)
	}
	role, err := PeekRole(home)
	if err != nil {
		t.Fatalf("PeekRole: %v", err)
	}
	if role != RoleAdmin {
		t.Fatalf("PeekRole = %q, want %q", role, RoleAdmin)
	}
}

func TestPeekRole_Client(t *testing.T) {
	home := setupHome(t)
	if err := SaveClient(home, clientFixture()); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	role, err := PeekRole(home)
	if err != nil {
		t.Fatalf("PeekRole: %v", err)
	}
	if role != RoleClient {
		t.Fatalf("PeekRole = %q, want %q", role, RoleClient)
	}
}

func TestPeekRole_MissingFile(t *testing.T) {
	home := setupHome(t)
	role, err := PeekRole(home)
	if err != nil {
		t.Fatalf("PeekRole: %v", err)
	}
	if role != RoleUninitialized {
		t.Fatalf("PeekRole = %q, want uninitialized", role)
	}
}

func TestPeekRole_MalformedFile(t *testing.T) {
	home := setupHome(t)
	if err := os.WriteFile(ConfigPath(home), []byte("{not json"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := PeekRole(home); err == nil {
		t.Fatalf("PeekRole on malformed = nil, want error")
	}
}

func TestSaveAdmin_JSONFieldsMatchSpec(t *testing.T) {
	home := setupHome(t)
	if err := SaveAdmin(home, adminFixture()); err != nil {
		t.Fatalf("SaveAdmin: %v", err)
	}
	data, err := os.ReadFile(ConfigPath(home))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"schema", "role", "store_id", "repo", "admin", "commit_author"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("admin json missing key %q", k)
		}
	}
	repo, _ := raw["repo"].(map[string]any)
	for _, k := range []string{"owner", "name", "remote_https", "remote_ssh", "default_branch"} {
		if _, ok := repo[k]; !ok {
			t.Errorf("repo json missing key %q", k)
		}
	}
}
