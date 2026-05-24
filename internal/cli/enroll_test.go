package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
)

var enrollRequestBranchRe = regexp.MustCompile(`^refs/heads/request/rq_[a-z2-7]{16}$`)

func collectEnrollRequestRefs(t *testing.T, bareURL string) []string {
	t.Helper()
	bareDir := strings.TrimPrefix(bareURL, "file://")
	repo, err := gogit.PlainOpen(bareDir)
	if err != nil {
		t.Fatalf("open bare: %v", err)
	}
	refs, err := repo.References()
	if err != nil {
		t.Fatalf("refs: %v", err)
	}
	var out []string
	_ = refs.ForEach(func(r *plumbing.Reference) error {
		name := r.Name().String()
		if strings.HasPrefix(name, "refs/heads/request/") {
			out = append(out, name)
		}
		return nil
	})
	return out
}

func setupAdminStore(t *testing.T) (adminHome, bareURL string) {
	t.Helper()
	a, _, home := newTestApp(t)
	url := bareRepo(t)
	flags := &initFlags{
		owner:    "GonzaloAlvarez",
		repo:     "kauket-store",
		private:  true,
		remote:   url,
		noGitHub: true,
		yes:      true,
	}
	if err := runInit(context.Background(), a, flags); err != nil {
		t.Fatalf("admin init: %v", err)
	}
	return home, url
}

func TestEnrollSuccess(t *testing.T) {
	_, bareURL := setupAdminStore(t)

	clientApp, fake, clientHome := newTestApp(t)
	flags := &enrollFlags{
		requests: []string{"ssh"},
		name:     "machine2",
		remote:   bareURL,
		yes:      true,
	}
	if err := runEnroll(context.Background(), clientApp, flags); err != nil {
		t.Fatalf("runEnroll: %v", err)
	}

	if len(fake.Lines) != 3 {
		t.Fatalf("expected 3 output lines, got %d: %v", len(fake.Lines), fake.Lines)
	}
	if !strings.HasPrefix(fake.Lines[0], "created enrollment request rq_") {
		t.Fatalf("first line %q does not start with created enrollment request rq_", fake.Lines[0])
	}
	if fake.Lines[1] != "requested profiles: ssh" {
		t.Fatalf("second line %q, want %q", fake.Lines[1], "requested profiles: ssh")
	}
	if fake.Lines[2] != "waiting for approval" {
		t.Fatalf("third line %q, want %q", fake.Lines[2], "waiting for approval")
	}

	wantFiles := []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Join(clientHome, "identities", "host.txt"), 0o600},
		{filepath.Join(clientHome, "git", "deploy_key"), 0o600},
		{filepath.Join(clientHome, "git", "deploy_key.pub"), 0o644},
		{filepath.Join(clientHome, "config.json"), 0o600},
	}
	for _, wf := range wantFiles {
		info, err := os.Stat(wf.path)
		if err != nil {
			t.Fatalf("expected file %s missing: %v", wf.path, err)
		}
		if runtime.GOOS != "windows" {
			got := info.Mode().Perm()
			if got != wf.mode {
				t.Fatalf("mode for %s: want %v, got %v", wf.path, wf.mode, got)
			}
		}
	}

	role, err := config.PeekRole(clientHome)
	if err != nil {
		t.Fatalf("peek role: %v", err)
	}
	if role != config.RoleClient {
		t.Fatalf("expected role client, got %q", role)
	}
	cfg, err := config.LoadClient(clientHome)
	if err != nil {
		t.Fatalf("load client: %v", err)
	}
	if cfg.Host.ID == "" || !strings.HasPrefix(cfg.Host.ID, "h_") {
		t.Fatalf("host id missing or wrong prefix: %q", cfg.Host.ID)
	}
	if cfg.Host.DisplayName != "machine2" {
		t.Fatalf("display name: got %q want machine2", cfg.Host.DisplayName)
	}
	if cfg.Host.IdentityPath != filepath.Join("identities", "host.txt") {
		t.Fatalf("identity path: got %q", cfg.Host.IdentityPath)
	}
	if cfg.Host.DeployKeyPath != filepath.Join("git", "deploy_key") {
		t.Fatalf("deploy key path: got %q", cfg.Host.DeployKeyPath)
	}
	if cfg.CommitAuthor.Name != "kauket-"+cfg.Host.ID {
		t.Fatalf("commit author name: got %q want kauket-%s", cfg.CommitAuthor.Name, cfg.Host.ID)
	}
	if cfg.CommitAuthor.Email != "kauket@"+cfg.Host.ID+".local" {
		t.Fatalf("commit author email: got %q want kauket@%s.local", cfg.CommitAuthor.Email, cfg.Host.ID)
	}
	if cfg.Repo.RemoteHTTPS != bareURL {
		t.Fatalf("repo remote https: got %q want %q", cfg.Repo.RemoteHTTPS, bareURL)
	}
	if cfg.Repo.RemoteSSH != "" {
		t.Fatalf("repo remote ssh should be empty for file remote, got %q", cfg.Repo.RemoteSSH)
	}

	refs := collectEnrollRequestRefs(t, bareURL)
	if len(refs) != 1 {
		t.Fatalf("expected 1 request ref on bare, got %v", refs)
	}
	if !enrollRequestBranchRe.MatchString(refs[0]) {
		t.Fatalf("ref %q does not match %s", refs[0], enrollRequestBranchRe)
	}

	bareDir := strings.TrimPrefix(bareURL, "file://")
	bare, err := gogit.PlainOpen(bareDir)
	if err != nil {
		t.Fatalf("open bare: %v", err)
	}
	ref, err := bare.Reference(plumbing.ReferenceName(refs[0]), true)
	if err != nil {
		t.Fatalf("ref %s: %v", refs[0], err)
	}
	commit, err := bare.CommitObject(ref.Hash())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if commit.Author.Email != "kauket@"+cfg.Host.ID+".local" {
		t.Fatalf("commit author email leak: got %q", commit.Author.Email)
	}
	if commit.Author.Name != "kauket-"+cfg.Host.ID {
		t.Fatalf("commit author name leak: got %q", commit.Author.Name)
	}
	if strings.Contains(commit.Author.Email, "gonzaloab@gmail.com") {
		t.Fatalf("commit author leaks admin email: %q", commit.Author.Email)
	}
	osHostname, _ := os.Hostname()
	if osHostname != "" && strings.Contains(commit.Author.Email, osHostname) {
		t.Fatalf("commit author leaks os hostname %q: %q", osHostname, commit.Author.Email)
	}
}

func TestEnrollRefusesAdminRole(t *testing.T) {
	a, _, home := newTestApp(t)
	adminCfg := &config.Admin{
		Schema:  config.ConfigSchema,
		Role:    config.RoleAdmin,
		StoreID: "ks_admin",
		Repo:    config.DefaultRepoInfo("GonzaloAlvarez", "kauket-store"),
		Admin: config.AdminInfo{
			RecipientID:  "ar_admin",
			IdentityPath: "identities/admin.txt",
		},
	}
	if err := config.SaveAdmin(home, adminCfg); err != nil {
		t.Fatalf("save admin: %v", err)
	}
	flags := &enrollFlags{
		requests: []string{"ssh"},
		remote:   bareRepo(t),
		yes:      true,
	}
	err := runEnroll(context.Background(), a, flags)
	if err == nil {
		t.Fatalf("expected error when enrolling on admin home")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %d", exitErr.Code)
	}
	if !strings.Contains(err.Error(), "admin") {
		t.Fatalf("expected admin mention, got %q", err.Error())
	}
}

func TestEnrollRefusesAlreadyEnrolled(t *testing.T) {
	a, _, home := newTestApp(t)
	clientCfg := &config.Client{
		Schema:  config.ConfigSchema,
		Role:    config.RoleClient,
		StoreID: "ks_test",
		Host: config.HostInfo{
			ID:           "h_test1234567890",
			IdentityPath: "identities/host.txt",
		},
		Repo: config.DefaultRepoInfo("GonzaloAlvarez", "kauket-store"),
	}
	if err := config.SaveClient(home, clientCfg); err != nil {
		t.Fatalf("save client: %v", err)
	}
	flags := &enrollFlags{
		requests: []string{"ssh"},
		remote:   bareRepo(t),
		yes:      true,
	}
	err := runEnroll(context.Background(), a, flags)
	if err == nil {
		t.Fatalf("expected error on already enrolled")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %d", exitErr.Code)
	}
	if !strings.Contains(err.Error(), "already enrolled") {
		t.Fatalf("expected 'already enrolled' mention, got %q", err.Error())
	}
}

func TestEnrollOfflineMode(t *testing.T) {
	_, bareURL := setupAdminStore(t)

	clientApp, fake, clientHome := newTestApp(t)
	flags := &enrollFlags{
		requests: []string{"ssh"},
		name:     "machine2",
		remote:   bareURL,
		offline:  true,
		yes:      true,
	}
	if err := runEnroll(context.Background(), clientApp, flags); err != nil {
		t.Fatalf("runEnroll offline: %v", err)
	}

	if len(fake.Lines) < 3 {
		t.Fatalf("expected at least 3 output lines, got %d: %v", len(fake.Lines), fake.Lines)
	}
	if fake.Lines[0] != "created offline enrollment request" {
		t.Fatalf("first line %q, want 'created offline enrollment request'", fake.Lines[0])
	}
	var codeLine string
	for _, l := range fake.Lines {
		if strings.HasPrefix(l, "kauket approve --request-code ") {
			codeLine = l
			break
		}
	}
	if codeLine == "" {
		t.Fatalf("missing 'kauket approve --request-code ...' line, got %v", fake.Lines)
	}
	encoded := strings.TrimPrefix(codeLine, "kauket approve --request-code ")
	ct, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode of request code: %v", err)
	}
	if len(ct) == 0 {
		t.Fatalf("decoded ciphertext is empty")
	}
	if !strings.Contains(string(ct), "age-encryption") {
		t.Fatalf("ciphertext lacks age header marker; first 64 bytes: %q", limitString(string(ct), 64))
	}

	refs := collectEnrollRequestRefs(t, bareURL)
	if len(refs) != 0 {
		t.Fatalf("offline mode pushed request branches: %v", refs)
	}

	cfg, err := config.LoadClient(clientHome)
	if err != nil {
		t.Fatalf("load client offline: %v", err)
	}
	if cfg.Host.ID == "" {
		t.Fatalf("host id missing on offline enroll")
	}
}

func TestEnrollRequiresRequestFlag(t *testing.T) {
	_, bareURL := setupAdminStore(t)
	clientApp, _, _ := newTestApp(t)
	flags := &enrollFlags{
		requests: nil,
		remote:   bareURL,
		yes:      true,
	}
	err := runEnroll(context.Background(), clientApp, flags)
	if err == nil {
		t.Fatalf("expected error when --request is missing")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %d", exitErr.Code)
	}
}

func TestEnrollRequiresRemoteOrRepo(t *testing.T) {
	clientApp, _, _ := newTestApp(t)
	flags := &enrollFlags{
		requests: []string{"ssh"},
		yes:      true,
	}
	t.Setenv("KAUKET_REPO", "")
	err := runEnroll(context.Background(), clientApp, flags)
	if err == nil {
		t.Fatalf("expected error when neither --remote nor --repo is set")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %d", exitErr.Code)
	}
}

func TestEnrollRequestEncryptedToAdminRecipient(t *testing.T) {
	adminHome, bareURL := setupAdminStore(t)

	clientApp, _, _ := newTestApp(t)
	flags := &enrollFlags{
		requests: []string{"ssh"},
		name:     "machine2",
		remote:   bareURL,
		yes:      true,
	}
	if err := runEnroll(context.Background(), clientApp, flags); err != nil {
		t.Fatalf("runEnroll: %v", err)
	}

	bareDir := strings.TrimPrefix(bareURL, "file://")
	bare, err := gogit.PlainOpen(bareDir)
	if err != nil {
		t.Fatalf("open bare: %v", err)
	}
	refs := collectEnrollRequestRefs(t, bareURL)
	if len(refs) != 1 {
		t.Fatalf("want 1 branch, got %v", refs)
	}
	ref, err := bare.Reference(plumbing.ReferenceName(refs[0]), true)
	if err != nil {
		t.Fatalf("ref: %v", err)
	}
	commit, err := bare.CommitObject(ref.Hash())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if commit.Message != "kauket: submit request" {
		t.Fatalf("unexpected commit message %q", commit.Message)
	}
	tree, err := commit.Tree()
	if err != nil {
		t.Fatalf("tree: %v", err)
	}
	requestID := strings.TrimPrefix(refs[0], "refs/heads/request/")
	file, err := tree.File("requests/" + requestID + ".age")
	if err != nil {
		t.Fatalf("file: %v", err)
	}
	r, err := file.Reader()
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	defer r.Close()
	var data []byte
	buf := make([]byte, 4096)
	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if readErr != nil {
			break
		}
	}
	adminIdentityPath := filepath.Join(adminHome, "identities", "admin.txt")
	got, err := bundle.DecodeRequest(data, agebox.FileIdentityProvider{Path: adminIdentityPath}, bundle.Ed25519Verifier{})
	if err != nil {
		t.Fatalf("admin cannot decrypt request: %v", err)
	}
	if got.RequestID != requestID {
		t.Fatalf("request id mismatch: got %q want %q", got.RequestID, requestID)
	}
	if got.Host.DisplayName != "machine2" {
		t.Fatalf("display name mismatch: %q", got.Host.DisplayName)
	}
	if len(got.Requested.Profiles) != 1 || got.Requested.Profiles[0] != "ssh" {
		t.Fatalf("profiles: %v", got.Requested.Profiles)
	}
}
