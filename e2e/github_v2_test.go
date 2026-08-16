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

	res := runKauket(t, bin, kauketHome, home, "init", "--recovery-out", recoveryOut,
		"--owner", owner, "--repo", repo, "--yes")
	if res.err != nil {
		t.Fatalf("init: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
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

func TestGitHubWriteJourney(t *testing.T) {
	owner, cleanupRepo := githubJourneySetup(t)
	skipSSH := os.Getenv("KAUKET_GITHUB_E2E_SKIP_SSH") == "1"
	repo := fmt.Sprintf("kauket-e2e-%d", time.Now().UnixNano())
	repoSlug := owner + "/" + repo
	bin := buildBinary(t)
	defer cleanupRepo(repoSlug)

	root := mustResolvedTempRoot(t)
	adminHome := filepath.Join(root, "admin-home")
	adminKauket := filepath.Join(adminHome, ".config", "kauket")
	clientHome := filepath.Join(root, "client-home")
	clientKauket := filepath.Join(clientHome, ".config", "kauket")
	mustMkdir(t, adminHome, 0o700)
	mustMkdir(t, clientHome, 0o700)

	res := runKauket(t, bin, adminKauket, adminHome, "init", "--owner", owner, "--repo", repo, "--recovery-out", filepath.Join(root, "recovery"), "--yes")
	if res.err != nil {
		t.Fatalf("init: %v\nstderr:%s", res.err, res.stderr)
	}
	seed := filepath.Join(adminHome, "src", "seed")
	mustMkdir(t, filepath.Dir(seed), 0o700)
	if err := os.WriteFile(seed, []byte("SEED CONTENT"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "add", "ssh.main_private_key", seed)
	if res.err != nil {
		t.Fatalf("add: %v\nstderr:%s", res.err, res.stderr)
	}
	res = runKauket(t, bin, clientKauket, clientHome, "request", "ssh", "--repo", repoSlug, "--name", randomEnrollName(), "--yes")
	if res.err != nil {
		t.Fatalf("enroll: %v\nstderr:%s", res.err, res.stderr)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve: %v\nstderr:%s", res.err, res.stderr)
	}

	hostID := readHostID(t, clientKauket)
	token := filepath.Join(adminHome, "src", "token")
	if err := os.WriteFile(token, []byte("JOURNEY TOKEN"), 0o600); err != nil {
		t.Fatalf("token: %v", err)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "add", "cloud.vendor.api_token", token, "--dest", "/etc/cloud/token")
	if res.err != nil {
		t.Fatalf("v2 add: %v\nstderr:%s", res.err, res.stderr)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "grant", hostID, "cloud/vendor")
	if res.err != nil {
		t.Fatalf("grant: %v\nstderr:%s", res.err, res.stderr)
	}

	if !skipSSH {
		res = runKauket(t, bin, clientKauket, clientHome, "get", "cloud.vendor.api_token", "--stdout")
		if res.err != nil || res.stdout != "JOURNEY TOKEN" {
			t.Fatalf("client SSH get: err=%v out=%q stderr=%s", res.err, res.stdout, res.stderr)
		}
	}

	res = runKauket(t, bin, adminKauket, adminHome, "revoke", hostID, "cloud/vendor")
	if res.err != nil {
		t.Fatalf("revoke: %v\nstderr:%s", res.err, res.stderr)
	}
	if !strings.Contains(res.stdout, "rotate these secrets") {
		t.Fatalf("revoke output: %q", res.stdout)
	}
	if !skipSSH {
		res = runKauket(t, bin, clientKauket, clientHome, "get", "cloud.vendor.api_token", "--stdout")
		if res.err == nil || exitCodeOf(res.err) != 5 {
			t.Fatalf("post-revoke get should exit 5, got %v", res.err)
		}
	}
	res = runKauket(t, bin, adminKauket, adminHome, "verify")
	if res.err != nil {
		t.Fatalf("verify: %v\nstderr:%s", res.err, res.stderr)
	}
	if err := runLeakScan(t, filepath.Join(roleHomePath(adminKauket, "admin"), "repo")); err != nil {
		t.Fatalf("leak scan: %v", err)
	}
}

func TestGitHubRequestJourney(t *testing.T) {
	owner, cleanupRepo := githubJourneySetup(t)
	skipSSH := os.Getenv("KAUKET_GITHUB_E2E_SKIP_SSH") == "1"
	repo := fmt.Sprintf("kauket-e2e-%d", time.Now().UnixNano())
	repoSlug := owner + "/" + repo
	bin := buildBinary(t)
	defer cleanupRepo(repoSlug)

	root := mustResolvedTempRoot(t)
	founderHome := filepath.Join(root, "founder-home")
	founderKauket := filepath.Join(founderHome, ".config", "kauket")
	clientHome := filepath.Join(root, "client-home")
	clientKauket := filepath.Join(clientHome, ".config", "kauket")
	mustMkdir(t, founderHome, 0o700)
	mustMkdir(t, clientHome, 0o700)

	res := runKauket(t, bin, founderKauket, founderHome, "init", "--recovery-out", filepath.Join(root, "recovery"),
		"--owner", owner, "--repo", repo, "--yes")
	if res.err != nil {
		t.Fatalf("init: %v\nstderr:%s", res.err, res.stderr)
	}
	first := filepath.Join(founderHome, "src", "first")
	second := filepath.Join(founderHome, "src", "second")
	mustMkdir(t, filepath.Dir(first), 0o700)
	if err := os.WriteFile(first, []byte("FIRST SECRET"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(second, []byte("SECOND SECRET"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	res = runKauket(t, bin, founderKauket, founderHome, "add", "cloud.vendor.api_token", first, "--dest", "/etc/cloud/token")
	if res.err != nil {
		t.Fatalf("add first: %v\nstderr:%s", res.err, res.stderr)
	}
	res = runKauket(t, bin, founderKauket, founderHome, "add", "other.area.second_secret", second, "--dest", "/etc/second")
	if res.err != nil {
		t.Fatalf("add second: %v\nstderr:%s", res.err, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "request", "cloud/vendor", "--repo", repoSlug, "--name", randomEnrollName(), "--yes")
	if res.err != nil {
		t.Fatalf("v2 enroll: %v\nstderr:%s", res.err, res.stderr)
	}
	if !strings.Contains(res.stdout, "requested paths: cloud/vendor") {
		t.Fatalf("enroll output: %q", res.stdout)
	}
	res = runKauket(t, bin, founderKauket, founderHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve enrollment: %v\nstderr:%s", res.err, res.stderr)
	}

	keys, err := ghListDeployKeys(t, repoSlug)
	if err != nil {
		t.Fatalf("list deploy keys: %v", err)
	}
	foundKey := false
	for _, k := range keys {
		if strings.HasPrefix(k.Title, "kauket h_") && k.ReadOnly {
			foundKey = true
		}
	}
	if !foundKey {
		t.Fatalf("no read-only kauket deploy key registered on v2 store; keys=%+v", keys)
	}

	if skipSSH {
		t.Logf("KAUKET_GITHUB_E2E_SKIP_SSH=1; skipping SSH reads")
		return
	}
	res = runKauket(t, bin, clientKauket, clientHome, "get", "cloud.vendor.api_token", "--stdout")
	if res.err != nil || res.stdout != "FIRST SECRET" {
		t.Fatalf("client get: err=%v out=%q stderr=%s", res.err, res.stdout, res.stderr)
	}
	res = runKauket(t, bin, clientKauket, clientHome, "get", "other.area.second_secret", "--stdout")
	if res.err == nil || exitCodeOf(res.err) != 5 {
		t.Fatalf("unrequested secret should exit 5, got %v", res.err)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "request", "other/area", "--yes")
	if res.err != nil {
		t.Fatalf("request: %v\nstderr:%s", res.err, res.stderr)
	}
	if !strings.Contains(res.stdout, "created access request rq_") {
		t.Fatalf("request output: %q", res.stdout)
	}
	res = runKauket(t, bin, founderKauket, founderHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve access request: %v\nstderr:%s", res.err, res.stderr)
	}
	res = runKauket(t, bin, clientKauket, clientHome, "get", "other.area.second_secret", "--stdout")
	if res.err != nil || res.stdout != "SECOND SECRET" {
		t.Fatalf("post-request get: err=%v out=%q stderr=%s", res.err, res.stdout, res.stderr)
	}
	res = runKauket(t, bin, clientKauket, clientHome, "verify")
	if res.err != nil {
		t.Fatalf("client verify: %v\nstderr:%s", res.err, res.stderr)
	}
	if err := runLeakScan(t, filepath.Join(roleHomePath(founderKauket, "admin"), "repo")); err != nil {
		t.Fatalf("leak scan: %v", err)
	}
}

func TestGitHubMultiOwnerJourney(t *testing.T) {
	owner, cleanupRepo := githubJourneySetup(t)
	skipSSH := os.Getenv("KAUKET_GITHUB_E2E_SKIP_SSH") == "1"
	repo := fmt.Sprintf("kauket-e2e-%d", time.Now().UnixNano())
	repoSlug := owner + "/" + repo
	bin := buildBinary(t)
	defer cleanupRepo(repoSlug)

	root := mustResolvedTempRoot(t)
	founderHome := filepath.Join(root, "founder-home")
	founderKauket := filepath.Join(founderHome, ".config", "kauket")
	userHome := filepath.Join(root, "user-home")
	userKauket := filepath.Join(userHome, ".config", "kauket")
	clientHome := filepath.Join(root, "client-home")
	clientKauket := filepath.Join(clientHome, ".config", "kauket")
	mustMkdir(t, founderHome, 0o700)
	mustMkdir(t, userHome, 0o700)
	mustMkdir(t, clientHome, 0o700)

	res := runKauket(t, bin, founderKauket, founderHome, "init", "--recovery-out", filepath.Join(root, "recovery"),
		"--owner", owner, "--repo", repo, "--yes")
	if res.err != nil {
		t.Fatalf("init: %v\nstderr:%s", res.err, res.stderr)
	}
	src := filepath.Join(founderHome, "src", "token")
	mustMkdir(t, filepath.Dir(src), 0o700)
	if err := os.WriteFile(src, []byte("MULTIOWNER TOKEN"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	res = runKauket(t, bin, founderKauket, founderHome, "add", "cloud.vendor.api_token", src, "--dest", "/etc/cloud/token")
	if res.err != nil {
		t.Fatalf("add: %v\nstderr:%s", res.err, res.stderr)
	}

	res = runKauket(t, bin, userKauket, userHome, "join", "--repo", repoSlug, "--request", "cloud/vendor", "--name", "co-owner", "--yes")
	if res.err != nil {
		t.Fatalf("join: %v\nstderr:%s", res.err, res.stderr)
	}
	res = runKauket(t, bin, founderKauket, founderHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve join: %v\nstderr:%s", res.err, res.stderr)
	}

	userID := ""
	userCfgBytes, err := os.ReadFile(filepath.Join(roleHomePath(userKauket, "admin"), "config.json"))
	if err != nil {
		t.Fatalf("read user config: %v", err)
	}
	for _, line := range strings.Split(string(userCfgBytes), "\n") {
		if strings.Contains(line, `"identity_id"`) {
			parts := strings.Split(line, `"`)
			userID = parts[3]
		}
	}
	if !strings.HasPrefix(userID, "i_") {
		t.Fatalf("user identity id not found: %q", userID)
	}

	res = runKauket(t, bin, founderKauket, founderHome, "grant", userID, "cloud/vendor", "--owner", "--yes")
	if res.err != nil {
		t.Fatalf("grant --owner: %v\nstderr:%s", res.err, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "request", "cloud/vendor", "--repo", repoSlug, "--name", randomEnrollName(), "--yes")
	if res.err != nil {
		t.Fatalf("enroll: %v\nstderr:%s", res.err, res.stderr)
	}
	res = runKauket(t, bin, founderKauket, founderHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve enrollment: %v\nstderr:%s", res.err, res.stderr)
	}
	hostID := readHostID(t, clientKauket)

	res = runKauket(t, bin, userKauket, userHome, "revoke", hostID, "cloud/vendor")
	if res.err != nil {
		t.Fatalf("second-owner revoke: %v\nstderr:%s", res.err, res.stderr)
	}
	if !strings.Contains(res.stdout, "revoked "+hostID) {
		t.Fatalf("revoke output: %q", res.stdout)
	}
	res = runKauket(t, bin, userKauket, userHome, "grant", hostID, "cloud/vendor")
	if res.err != nil {
		t.Fatalf("second-owner grant: %v\nstderr:%s", res.err, res.stderr)
	}

	if !skipSSH {
		res = runKauket(t, bin, clientKauket, clientHome, "get", "cloud.vendor.api_token", "--stdout")
		if res.err != nil || res.stdout != "MULTIOWNER TOKEN" {
			t.Fatalf("client get after user-signed grant: err=%v out=%q stderr=%s", res.err, res.stdout, res.stderr)
		}
	}

	res = runKauket(t, bin, founderKauket, founderHome, "verify")
	if res.err != nil {
		t.Fatalf("verify: %v\nstderr:%s", res.err, res.stderr)
	}
	if err := runLeakScan(t, filepath.Join(roleHomePath(founderKauket, "admin"), "repo")); err != nil {
		t.Fatalf("leak scan: %v", err)
	}
}

func TestGitHubRescueJourney(t *testing.T) {
	owner, cleanupRepo := githubJourneySetup(t)
	skipSSH := os.Getenv("KAUKET_GITHUB_E2E_SKIP_SSH") == "1"
	repo := fmt.Sprintf("kauket-e2e-%d", time.Now().UnixNano())
	repoSlug := owner + "/" + repo
	bin := buildBinary(t)
	defer cleanupRepo(repoSlug)

	root := mustResolvedTempRoot(t)
	founderHome := filepath.Join(root, "founder-home")
	founderKauket := filepath.Join(founderHome, ".config", "kauket")
	userHome := filepath.Join(root, "user-home")
	userKauket := filepath.Join(userHome, ".config", "kauket")
	mustMkdir(t, founderHome, 0o700)
	mustMkdir(t, userHome, 0o700)
	recoveryOut := filepath.Join(root, "recovery")

	res := runKauket(t, bin, founderKauket, founderHome, "init", "--recovery-out", recoveryOut,
		"--owner", owner, "--repo", repo, "--yes")
	if res.err != nil {
		t.Fatalf("init: %v\nstderr:%s", res.err, res.stderr)
	}
	src := filepath.Join(founderHome, "src", "token")
	mustMkdir(t, filepath.Dir(src), 0o700)
	if err := os.WriteFile(src, []byte("RESCUE JOURNEY TOKEN"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	res = runKauket(t, bin, founderKauket, founderHome, "add", "cloud.vendor.api_token", src, "--dest", "/etc/cloud/token")
	if res.err != nil {
		t.Fatalf("add: %v\nstderr:%s", res.err, res.stderr)
	}

	res = runKauket(t, bin, userKauket, userHome, "join", "--repo", repoSlug, "--request", "cloud/vendor", "--name", "successor", "--yes")
	if res.err != nil {
		t.Fatalf("join: %v\nstderr:%s", res.err, res.stderr)
	}
	res = runKauket(t, bin, founderKauket, founderHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve: %v\nstderr:%s", res.err, res.stderr)
	}

	userID := ""
	userCfgBytes, err := os.ReadFile(filepath.Join(roleHomePath(userKauket, "admin"), "config.json"))
	if err != nil {
		t.Fatalf("read user config: %v", err)
	}
	for _, line := range strings.Split(string(userCfgBytes), "\n") {
		if strings.Contains(line, `"identity_id"`) {
			userID = strings.Split(line, `"`)[3]
		}
	}
	if !strings.HasPrefix(userID, "i_") {
		t.Fatalf("user id not found")
	}

	res = runKauket(t, bin, founderKauket, founderHome, "rescue", "cloud/vendor",
		"--recovery-identity", filepath.Join(recoveryOut, "recovery-age.txt"),
		"--recovery-sign-key", filepath.Join(recoveryOut, "recovery-sign.key"),
		"--new-owner", userID)
	if res.err != nil {
		t.Fatalf("rescue: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "rescued cloud/vendor") {
		t.Fatalf("rescue output: %q", res.stdout)
	}

	res = runKauket(t, bin, founderKauket, founderHome, "inspect", "--as", userID)
	if res.err != nil {
		t.Fatalf("inspect: %v\nstderr:%s", res.err, res.stderr)
	}
	if !strings.Contains(res.stdout, "cloud.vendor.api_token") {
		t.Fatalf("inspect output: %q", res.stdout)
	}

	if !skipSSH {
		res = runKauket(t, bin, userKauket, userHome, "get", "cloud.vendor.api_token", "--stdout")
		if res.err != nil || res.stdout != "RESCUE JOURNEY TOKEN" {
			t.Fatalf("new owner get: err=%v out=%q stderr=%s", res.err, res.stdout, res.stderr)
		}
	}
	res = runKauket(t, bin, founderKauket, founderHome, "verify")
	if res.err != nil {
		t.Fatalf("verify: %v\nstderr:%s", res.err, res.stderr)
	}
	if err := runLeakScan(t, filepath.Join(roleHomePath(founderKauket, "admin"), "repo")); err != nil {
		t.Fatalf("leak scan: %v", err)
	}
}
