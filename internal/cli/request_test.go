package cli

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/model"
	"github.com/gonzaloalvarez/kauket/internal/ui"
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

func setupAdminStore(t *testing.T) (baseHome, adminHome, bareURL string) {
	t.Helper()
	a, _, home := newTestApp(t)
	url := bareRepo(t)
	flags := &initFlags{
		owner:       "GonzaloAlvarez",
		repo:        "kauket-store",
		remote:      url,
		yes:         true,
		recoveryOut: filepath.Join(t.TempDir(), "recovery"),
	}
	if err := runInit(context.Background(), a, flags); err != nil {
		t.Fatalf("admin init: %v", err)
	}
	return home, config.RoleHome(home, config.RoleAdmin), url
}

type failingShell struct{}

func (failingShell) LookPath(string) (string, error) { return "", exec.ErrNotFound }
func (failingShell) Run(context.Context, string, ...string) ([]byte, []byte, error) {
	return nil, nil, errors.New("no gh in tests")
}

type failingRoundTripper struct{}

func (failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no network in tests")
}

func TestRequestAutoEnrollSuccess(t *testing.T) {
	_, _, bareURL := setupAdminStore(t)

	clientApp, fake, clientBase := newTestApp(t)
	clientHome := config.RoleHome(clientBase, config.RoleClient)
	if err := runRequest(context.Background(), clientApp, []string{"ssh"}, &requestFlags{
		name: "machine2", remote: bareURL, yes: true,
	}); err != nil {
		t.Fatalf("runRequest: %v", err)
	}

	lines := make([]string, 0, len(fake.Lines))
	for _, l := range fake.Lines {
		if strings.HasPrefix(l, "warning: trust-on-first-use:") {
			continue
		}
		lines = append(lines, l)
	}
	if len(lines) != 5 {
		t.Fatalf("expected 5 output lines, got %d: %v", len(lines), fake.Lines)
	}
	if lines[0] != "not enrolled yet; enrolling this machine" {
		t.Fatalf("first line %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "enrolled as machine2 (h_") {
		t.Fatalf("second line %q", lines[1])
	}
	if !strings.HasPrefix(lines[2], "created enrollment request rq_") {
		t.Fatalf("third line %q does not start with created enrollment request rq_", lines[2])
	}
	if lines[3] != "requested paths: ssh" {
		t.Fatalf("fourth line %q, want %q", lines[3], "requested paths: ssh")
	}
	if lines[4] != "waiting for approval (run 'kauket approve' on your admin machine)" {
		t.Fatalf("fifth line %q", lines[4])
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

func TestRequestOnAdminHomeFilesAccessRequest(t *testing.T) {
	adminBase, adminHome, bareURL := setupAdminStore(t)

	fake := &ui.Fake{}
	a := &app.App{UI: fake, Home: adminBase}
	if err := runRequest(context.Background(), a, []string{"cloud/vendor"}, &requestFlags{yes: true}); err != nil {
		t.Fatalf("runRequest on admin home: %v", err)
	}

	joined := strings.Join(fake.Lines, "\n")
	if !strings.Contains(joined, "created access request rq_") {
		t.Fatalf("expected access request, got: %v", fake.Lines)
	}
	if _, err := config.LoadClient(config.RoleHome(adminBase, config.RoleClient)); err == nil {
		t.Fatalf("request on admin home must not create a client role")
	}
	if _, err := config.LoadAdmin(adminHome); err != nil {
		t.Fatalf("admin config should be untouched: %v", err)
	}
	refs := collectEnrollRequestRefs(t, bareURL)
	if len(refs) != 1 {
		t.Fatalf("expected 1 request ref on bare, got %v", refs)
	}
}

func TestRequestNoRepoSourceAndNoGitHub(t *testing.T) {
	clientApp, _, _ := newTestApp(t)
	clientApp.AuthShell = failingShell{}
	clientApp.HTTPClient = &http.Client{Transport: failingRoundTripper{}}
	t.Setenv("KAUKET_REPO", "")
	err := runRequest(context.Background(), clientApp, []string{"ssh"}, &requestFlags{yes: true})
	if err == nil {
		t.Fatalf("expected error when no repo source and gh detection fails")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %d", exitErr.Code)
	}
	if !strings.Contains(err.Error(), "--repo owner/repo or --remote") {
		t.Fatalf("expected repo-source hint, got %q", err.Error())
	}
}

func TestRequestKeyRequiresSinglePath(t *testing.T) {
	_, _, bareURL := setupAdminStore(t)
	clientApp, _, _ := newTestApp(t)
	err := runRequest(context.Background(), clientApp, []string{"ssh", "aws"}, &requestFlags{
		key: "main", remote: bareURL, yes: true,
	})
	if err == nil {
		t.Fatalf("expected error for --key with multiple paths")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %v", err)
	}
}

func TestRequestAutoEnrollMultiplePaths(t *testing.T) {
	_, adminHome, bareURL := setupAdminStore(t)

	clientApp, _, _ := newTestApp(t)
	if err := runRequest(context.Background(), clientApp, []string{"ssh", "aws/profile"}, &requestFlags{
		name: "machine2", remote: bareURL, yes: true,
	}); err != nil {
		t.Fatalf("runRequest: %v", err)
	}
	got := decodeSingleRequest(t, bareURL, adminHome)
	if len(got.Requested.Paths) != 2 || got.Requested.Paths[0] != "ssh" || got.Requested.Paths[1] != "aws/profile" {
		t.Fatalf("paths: %v", got.Requested.Paths)
	}
}

func TestRequestEncryptedToAdminRecipient(t *testing.T) {
	_, adminHome, bareURL := setupAdminStore(t)

	clientApp, _, _ := newTestApp(t)
	if err := runRequest(context.Background(), clientApp, []string{"ssh"}, &requestFlags{
		name: "machine2", remote: bareURL, yes: true,
	}); err != nil {
		t.Fatalf("runRequest: %v", err)
	}
	got := decodeSingleRequest(t, bareURL, adminHome)
	if got.Host.DisplayName != "machine2" {
		t.Fatalf("display name mismatch: %q", got.Host.DisplayName)
	}
	if len(got.Requested.Paths) != 1 || got.Requested.Paths[0] != "ssh" {
		t.Fatalf("paths: %v", got.Requested.Paths)
	}
}

func decodeSingleRequest(t *testing.T, bareURL, adminHome string) model.Request {
	t.Helper()
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
	return got
}

type cannedGHShell struct{ login string }

func (cannedGHShell) LookPath(string) (string, error) { return "/usr/local/bin/gh", nil }
func (s cannedGHShell) Run(_ context.Context, _ string, args ...string) ([]byte, []byte, error) {
	out := "github.com\n  ✓ Logged in to github.com account " + s.login + " (keyring)\n  - Active account: true\n  - Token scopes: 'repo', 'admin:public_key'\n"
	return []byte(out), nil, nil
}

func TestRequestDetectedRepoConfirmDeclined(t *testing.T) {
	clientApp, fake, _ := newTestApp(t)
	clientApp.AuthShell = cannedGHShell{login: "testowner"}
	fake.ConfirmReply = false
	t.Setenv("KAUKET_REPO", "")
	err := runRequest(context.Background(), clientApp, []string{"ssh"}, &requestFlags{})
	if err == nil {
		t.Fatalf("expected error when repo confirmation is declined")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %v", err)
	}
	joined := strings.Join(fake.Lines, "\n")
	if !strings.Contains(joined, "not enrolled yet; enrolling this machine") {
		t.Fatalf("missing enrollment banner: %v", fake.Lines)
	}
}
