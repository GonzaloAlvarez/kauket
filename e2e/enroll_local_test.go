//go:build e2e

package e2e_test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

var enrollE2EBranchRe = regexp.MustCompile(`^refs/heads/request/rq_[a-z2-7]{16}$`)

func collectRequestRefs(t *testing.T, bareDir string) []string {
	t.Helper()
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

func TestEnrollLocalE2E(t *testing.T) {
	bin := buildBinary(t)

	root := t.TempDir()
	adminHome := filepath.Join(root, "admin-home")
	adminKauket := filepath.Join(adminHome, ".config", "kauket")
	clientHome := filepath.Join(root, "machine2-home")
	clientKauket := filepath.Join(clientHome, ".config", "kauket")
	bareDir := filepath.Join(root, "bare-remote.git")

	if err := os.MkdirAll(adminHome, 0o700); err != nil {
		t.Fatalf("mkdir admin home: %v", err)
	}
	if err := os.MkdirAll(clientHome, 0o700); err != nil {
		t.Fatalf("mkdir client home: %v", err)
	}
	remoteURL := setupBareRemote(t, bareDir)

	res := runKauket(t, bin, adminKauket, adminHome, "init", "--remote", remoteURL, "--no-github", "--yes")
	if res.err != nil {
		t.Fatalf("admin init failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "enroll", "--remote", remoteURL, "--request", "ssh", "--name", "machine2", "--yes")
	if res.err != nil {
		t.Fatalf("enroll failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	if !strings.Contains(res.stdout, "created enrollment request rq_") {
		t.Fatalf("expected 'created enrollment request rq_' in stdout, got: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "requested profiles: ssh") {
		t.Fatalf("expected 'requested profiles: ssh' in stdout, got: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "waiting for approval") {
		t.Fatalf("expected 'waiting for approval' in stdout, got: %q", res.stdout)
	}

	wantFiles := []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Join(clientKauket, "identities", "host.txt"), 0o600},
		{filepath.Join(clientKauket, "git", "deploy_key"), 0o600},
		{filepath.Join(clientKauket, "git", "deploy_key.pub"), 0o644},
		{filepath.Join(clientKauket, "config.json"), 0o600},
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

	refs := collectRequestRefs(t, bareDir)
	if len(refs) != 1 {
		t.Fatalf("expected 1 request branch on bare, got %v", refs)
	}
	if !enrollE2EBranchRe.MatchString(refs[0]) {
		t.Fatalf("ref %q does not match %s", refs[0], enrollE2EBranchRe)
	}

	cfgBytes, err := os.ReadFile(filepath.Join(clientKauket, "config.json"))
	if err != nil {
		t.Fatalf("read client config: %v", err)
	}
	cfg := string(cfgBytes)
	if !strings.Contains(cfg, `"role": "client"`) {
		t.Fatalf("client config missing role client, got: %s", cfg)
	}
	if !strings.Contains(cfg, `"display_name": "machine2"`) {
		t.Fatalf("client config missing display_name machine2, got: %s", cfg)
	}
	if !strings.Contains(cfg, `"identity_path": "identities/host.txt"`) &&
		!strings.Contains(cfg, `"identity_path": "identities\\host.txt"`) {
		t.Fatalf("client config missing identity_path, got: %s", cfg)
	}

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
	if commit.Message != "kauket: submit request" {
		t.Fatalf("unexpected commit message %q", commit.Message)
	}
	if strings.Contains(commit.Author.Email, "gonzaloab@gmail.com") {
		t.Fatalf("commit author leaks admin email: %q", commit.Author.Email)
	}
	osHostname, _ := os.Hostname()
	if osHostname != "" && strings.Contains(commit.Author.Email, osHostname) {
		t.Fatalf("commit author leaks os hostname %q: %q", osHostname, commit.Author.Email)
	}
	if !strings.HasPrefix(commit.Author.Name, "kauket-h_") {
		t.Fatalf("commit author name should start with kauket-h_, got: %q", commit.Author.Name)
	}
	if !strings.HasPrefix(commit.Author.Email, "kauket@h_") || !strings.HasSuffix(commit.Author.Email, ".local") {
		t.Fatalf("commit author email should be kauket@h_<id>.local, got: %q", commit.Author.Email)
	}
}

func TestEnrollLocalE2ERefusesAdminHome(t *testing.T) {
	bin := buildBinary(t)

	root := t.TempDir()
	adminHome := filepath.Join(root, "admin-home")
	adminKauket := filepath.Join(adminHome, ".config", "kauket")
	bareDir := filepath.Join(root, "bare-remote.git")
	if err := os.MkdirAll(adminHome, 0o700); err != nil {
		t.Fatalf("mkdir admin home: %v", err)
	}
	remoteURL := setupBareRemote(t, bareDir)

	res := runKauket(t, bin, adminKauket, adminHome, "init", "--remote", remoteURL, "--no-github", "--yes")
	if res.err != nil {
		t.Fatalf("admin init failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, adminKauket, adminHome, "enroll", "--remote", remoteURL, "--request", "ssh", "--yes")
	if res.err == nil {
		t.Fatalf("expected enroll on admin home to fail, got nil")
	}
	if !strings.Contains(res.stderr, "admin") {
		t.Fatalf("expected admin mention in stderr, got: %q", res.stderr)
	}
}
