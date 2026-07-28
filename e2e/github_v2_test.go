//go:build github_e2e

package e2e_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func githubJourneySetup(t *testing.T) (owner string, cleanupRepo func(slug string)) {
	t.Helper()
	if os.Getenv("KAUKET_GITHUB_E2E") != "1" {
		t.Skip("set KAUKET_GITHUB_E2E=1 to enable GitHub journeys")
	}
	owner = strings.TrimSpace(os.Getenv("KAUKET_GITHUB_OWNER"))
	if owner == "" {
		owner = "GonzaloAlvarez"
	}
	if err := ghAuthAsOwner(t, owner); err != nil {
		t.Skipf("gh not authenticated as %s: %v", owner, err)
	}
	if os.Getenv("GH_TOKEN") == "" {
		tokOut, err := exec.Command("gh", "auth", "token").Output()
		if err != nil {
			t.Skipf("could not capture gh auth token: %v", err)
		}
		t.Setenv("GH_TOKEN", strings.TrimSpace(string(tokOut)))
	}
	cleanupRepo = func(slug string) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "gh", "repo", "delete", slug, "--yes").CombinedOutput()
		if err != nil {
			t.Logf("WARNING: failed to delete test repo %s: %v\noutput: %s", slug, err, string(out))
			fmt.Fprintf(os.Stderr, "CLEANUP FAILED: please manually delete %s\n", slug)
		}
	}
	return owner, cleanupRepo
}

func TestGitHubV2InitJourney(t *testing.T) {
	owner, cleanupRepo := githubJourneySetup(t)
	repo := fmt.Sprintf("kauket-e2e-%d", time.Now().UnixNano())
	repoSlug := owner + "/" + repo
	bin := buildBinary(t)
	defer cleanupRepo(repoSlug)

	root := mustResolvedTempRoot(t)
	home := filepath.Join(root, "founder-home")
	kauketHome := filepath.Join(home, ".config", "kauket")
	mustMkdir(t, home, 0o700)
	recoveryOut := filepath.Join(root, "recovery")

	res := runKauket(t, bin, kauketHome, home, "init", "--v2", "--recovery-out", recoveryOut,
		"--owner", owner, "--repo", repo, "--private", "--yes")
	if res.err != nil {
		t.Fatalf("init --v2: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	view, err := ghRepoViewJSON(t, repoSlug)
	if err != nil {
		t.Fatalf("gh repo view: %v", err)
	}
	if !view.Private {
		t.Fatalf("repo %s must be private", repoSlug)
	}

	res = runKauket(t, bin, kauketHome, home, "verify")
	if res.err != nil {
		t.Fatalf("verify: %v\nstderr:%s", res.err, res.stderr)
	}
	if !strings.Contains(res.stdout, "verified 1 nodes, 0 entries") {
		t.Fatalf("verify output: %q", res.stdout)
	}
	res = runKauket(t, bin, kauketHome, home, "status")
	if res.err != nil || !strings.Contains(res.stdout, "schema: 2") {
		t.Fatalf("status: err=%v out=%q", res.err, res.stdout)
	}
}

func TestGitHubMigrateStoreJourney(t *testing.T) {
	owner, cleanupRepo := githubJourneySetup(t)
	skipSSH := os.Getenv("KAUKET_GITHUB_E2E_SKIP_SSH") == "1"
	repo := fmt.Sprintf("kauket-e2e-%d", time.Now().UnixNano())
	repoSlug := owner + "/" + repo
	bin := buildBinary(t)
	defer cleanupRepo(repoSlug)

	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	root := mustResolvedTempRoot(t)
	adminHome := filepath.Join(root, "admin-home")
	adminKauket := filepath.Join(adminHome, ".config", "kauket")
	clientHome := filepath.Join(root, "machine2-home")
	clientKauket := filepath.Join(clientHome, ".config", "kauket")
	mustMkdir(t, filepath.Join(adminHome, ".aws"), 0o700)
	mustMkdir(t, clientHome, 0o700)

	res := runKauket(t, bin, adminKauket, adminHome, "init", "--owner", owner, "--repo", repo, "--private", "--yes")
	if res.err != nil {
		t.Fatalf("init: %v\nstderr:%s", res.err, res.stderr)
	}

	adminKeyPath := filepath.Join(adminHome, ".ssh", "main_private_key.pem")
	generateEd25519KeyFile(t, adminKeyPath)
	res = runKauket(t, bin, adminKauket, adminHome, "add", "ssh.main_private_key", adminKeyPath)
	if res.err != nil {
		t.Fatalf("add: %v\nstderr:%s", res.err, res.stderr)
	}
	if err := os.WriteFile(filepath.Join(adminHome, ".aws", "config"), []byte("[profile amzn-wanfe]\nregion = us-west-2\n"), 0o600); err != nil {
		t.Fatalf("aws config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(adminHome, ".aws", "credentials"), []byte("[amzn-wanfe]\naws_access_key_id = AKIAJOURNEY\naws_secret_access_key = journeysecret\n"), 0o600); err != nil {
		t.Fatalf("aws creds: %v", err)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "add", "--aws-profile", "amzn-wanfe")
	if res.err != nil {
		t.Fatalf("add aws: %v\nstderr:%s", res.err, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "enroll", "--repo", repoSlug, "--request", "ssh", "--name", randomEnrollName(), "--yes")
	if res.err != nil {
		t.Fatalf("enroll: %v\nstderr:%s", res.err, res.stderr)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve: %v\nstderr:%s", res.err, res.stderr)
	}

	recoveryOut := filepath.Join(root, "recovery")
	res = runKauket(t, bin, adminKauket, adminHome, "migrate-store", "--recovery-out", recoveryOut, "--yes")
	if res.err != nil {
		t.Fatalf("migrate-store: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, adminKauket, adminHome, "verify")
	if res.err != nil {
		t.Fatalf("admin verify: %v\nstderr:%s", res.err, res.stderr)
	}

	adminRepo := filepath.Join(roleHomePath(adminKauket, "admin"), "repo")
	for _, p := range []string{"repo.json", "admin/vault.age"} {
		if _, err := os.Stat(filepath.Join(adminRepo, p)); err != nil {
			t.Fatalf("frozen v1 file missing: %v", err)
		}
	}

	if skipSSH {
		t.Logf("KAUKET_GITHUB_E2E_SKIP_SSH=1; skipping client SSH verification")
		return
	}
	res = runKauket(t, bin, clientKauket, clientHome, "get", "ssh.main_private_key", "--stdout")
	if res.err != nil {
		t.Fatalf("client get over SSH post-migration: %v\nstderr:%s", res.err, res.stderr)
	}
	adminBytes, err := os.ReadFile(adminKeyPath)
	if err != nil {
		t.Fatalf("read admin key: %v", err)
	}
	if res.stdout != string(adminBytes) {
		t.Fatalf("client content mismatch after migration")
	}
	res = runKauket(t, bin, clientKauket, clientHome, "get", "aws.profile.amzn-wanfe", "--stdout", "--no-sync")
	if res.err == nil || exitCodeOf(res.err) != 5 {
		t.Fatalf("ungranted get should exit 5, got %v", res.err)
	}
	res = runKauket(t, bin, clientKauket, clientHome, "verify", "--no-sync")
	if res.err != nil {
		t.Fatalf("client verify: %v\nstderr:%s", res.err, res.stderr)
	}
	if err := runLeakScan(t, adminRepo); err != nil {
		t.Fatalf("leak scan: %v", err)
	}
}
