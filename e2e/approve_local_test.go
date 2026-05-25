//go:build e2e

package e2e_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

func TestApproveLocalE2E(t *testing.T) {
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
		t.Fatalf("admin init: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "enroll", "--remote", remoteURL, "--request", "ssh", "--name", "machine2", "--yes")
	if res.err != nil {
		t.Fatalf("enroll: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	bareBefore, err := gogit.PlainOpen(bareDir)
	if err != nil {
		t.Fatalf("open bare before: %v", err)
	}
	var preRefs []string
	refs, _ := bareBefore.References()
	_ = refs.ForEach(func(r *plumbing.Reference) error {
		name := r.Name().String()
		if strings.HasPrefix(name, "refs/heads/request/") {
			preRefs = append(preRefs, name)
		}
		return nil
	})
	if len(preRefs) != 1 {
		t.Fatalf("setup: want 1 request ref pre-approve, got %v", preRefs)
	}

	res = runKauket(t, bin, adminKauket, adminHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "syncing store") {
		t.Fatalf("expected 'syncing store' in stdout, got: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "fetching pending requests") {
		t.Fatalf("expected 'fetching pending requests' in stdout, got: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, "request 1 approved") {
		t.Fatalf("expected 'request 1 approved' in stdout, got: %q", res.stdout)
	}

	bare, err := gogit.PlainOpen(bareDir)
	if err != nil {
		t.Fatalf("open bare: %v", err)
	}
	mainRef, err := bare.Reference(plumbing.NewBranchReferenceName("main"), true)
	if err != nil {
		t.Fatalf("resolve main: %v", err)
	}
	commit, err := bare.CommitObject(mainRef.Hash())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if commit.Message != "kauket: approve request" {
		t.Fatalf("expected approve commit on main, got %q", commit.Message)
	}
	tree, err := commit.Tree()
	if err != nil {
		t.Fatalf("tree: %v", err)
	}
	if _, err := tree.File("admin/vault.age"); err != nil {
		t.Fatalf("main missing admin/vault.age: %v", err)
	}
	var bundleEntries []string
	if subtree, err := tree.Tree("bundles"); err == nil {
		for _, e := range subtree.Entries {
			bundleEntries = append(bundleEntries, e.Name)
		}
	}
	hostBundleFound := false
	for _, name := range bundleEntries {
		if strings.HasPrefix(name, "h_") && strings.HasSuffix(name, ".age") {
			hostBundleFound = true
			break
		}
	}
	if !hostBundleFound {
		t.Fatalf("main tree missing bundles/h_*.age entry; entries: %v", bundleEntries)
	}

	refsAfter, _ := bare.References()
	var postRefs []string
	_ = refsAfter.ForEach(func(r *plumbing.Reference) error {
		name := r.Name().String()
		if strings.HasPrefix(name, "refs/heads/request/") {
			postRefs = append(postRefs, name)
		}
		return nil
	})
	if len(postRefs) != 0 {
		t.Fatalf("expected zero request branches after approve, got %v", postRefs)
	}
}
