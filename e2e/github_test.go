//go:build github_e2e

package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var hostIDTitleRe = regexp.MustCompile(`^kauket h_[a-z2-7]{16}$`)

type ghDeployKey struct {
	ID       int64  `json:"id"`
	Title    string `json:"title"`
	Key      string `json:"key"`
	ReadOnly bool   `json:"read_only"`
}

type ghRepoView struct {
	Name    string `json:"name"`
	Private bool   `json:"private"`
}

func TestGitHubInitEnrollApproveGet(t *testing.T) {
	if os.Getenv("KAUKET_GITHUB_E2E") != "1" {
		t.Skip("set KAUKET_GITHUB_E2E=1 to enable the GitHub E2E test")
	}
	skipSSH := os.Getenv("KAUKET_GITHUB_E2E_SKIP_SSH") == "1"

	owner := strings.TrimSpace(os.Getenv("KAUKET_GITHUB_OWNER"))
	if owner == "" {
		owner = "GonzaloAlvarez"
	}
	repo := fmt.Sprintf("kauket-e2e-%d", time.Now().Unix())
	repoSlug := fmt.Sprintf("%s/%s", owner, repo)

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

	bin := buildBinary(t)

	cleanedUp := false
	cleanup := func() {
		if cleanedUp {
			return
		}
		cleanedUp = true
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "gh", "repo", "delete", repoSlug, "--yes").CombinedOutput()
		if err != nil {
			t.Logf("WARNING: failed to delete test repo %s: %v\noutput: %s", repoSlug, err, string(out))
			fmt.Fprintf(os.Stderr, "CLEANUP FAILED: please manually delete %s\n", repoSlug)
		}
	}
	defer cleanup()

	root := mustResolvedTempRoot(t)
	adminHome := filepath.Join(root, "admin-home")
	adminKauket := filepath.Join(adminHome, ".config", "kauket")
	clientHome := filepath.Join(root, "machine2-home")
	clientKauket := filepath.Join(clientHome, ".config", "kauket")

	mustMkdir(t, adminHome, 0o700)
	mustMkdir(t, clientHome, 0o700)

	res := runKauket(t, bin, adminKauket, adminHome,
		"init", "--owner", owner, "--repo", repo, "--private", "--yes")
	if res.err != nil {
		t.Fatalf("init failed: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "initialized kauket store") {
		t.Fatalf("expected 'initialized kauket store' in stdout, got: %q", res.stdout)
	}

	view, err := ghRepoViewJSON(t, repoSlug)
	if err != nil {
		t.Fatalf("gh repo view: %v", err)
	}
	if view.Name != repo {
		t.Fatalf("gh repo view name mismatch: want %q got %q", repo, view.Name)
	}
	if !view.Private {
		t.Fatalf("expected repo %s to be private", repoSlug)
	}

	adminKeyPath := filepath.Join(adminHome, ".ssh", "main_private_key.pem")
	generateEd25519KeyFile(t, adminKeyPath)

	res = runKauket(t, bin, adminKauket, adminHome, "add", "ssh.main_private_key", adminKeyPath)
	if res.err != nil {
		t.Fatalf("admin add: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome,
		"enroll", "--repo", repoSlug, "--request", "ssh", "--name", randomEnrollName(), "--yes")
	if res.err != nil {
		t.Fatalf("enroll: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "created enrollment request rq_") {
		t.Fatalf("expected enroll to print created enrollment request, got: %q", res.stdout)
	}

	res = runKauket(t, bin, adminKauket, adminHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "request 1 approved") {
		t.Fatalf("expected approve to confirm request 1 approved, got: %q", res.stdout)
	}

	hostID := readHostID(t, clientKauket)
	keys, err := ghListDeployKeys(t, repoSlug)
	if err != nil {
		t.Fatalf("gh list deploy keys: %v", err)
	}
	var found *ghDeployKey
	for i := range keys {
		k := keys[i]
		if strings.HasPrefix(k.Title, "kauket ") {
			found = &k
			break
		}
	}
	if found == nil {
		t.Fatalf("no deploy key with kauket prefix found on %s; keys=%+v", repoSlug, keys)
	}
	if !hostIDTitleRe.MatchString(found.Title) {
		t.Fatalf("deploy key title %q does not match regex %s (expected 'kauket h_<id>', no hostname)", found.Title, hostIDTitleRe)
	}
	if !strings.Contains(found.Title, hostID) {
		t.Fatalf("deploy key title %q does not contain host_id %s", found.Title, hostID)
	}
	if !found.ReadOnly {
		t.Fatalf("deploy key %q must be read_only=true, got read_only=%v", found.Title, found.ReadOnly)
	}

	if skipSSH {
		t.Logf("KAUKET_GITHUB_E2E_SKIP_SSH=1 set; skipping SSH sync + install verification")
	} else {
		res = runKauket(t, bin, clientKauket, clientHome, "get", "ssh.main_private_key")
		if res.err != nil {
			t.Fatalf("client get over SSH deploy key: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stdout, "syncing store") {
			t.Fatalf("expected 'syncing store' in get stdout, got: %q", res.stdout)
		}
		if !strings.Contains(res.stdout, "creating ~/.ssh/main_private_key") {
			t.Fatalf("expected 'creating ~/.ssh/main_private_key' in get stdout, got: %q", res.stdout)
		}

		clientKeyPath := filepath.Join(clientHome, ".ssh", "main_private_key")
		info, err := os.Stat(clientKeyPath)
		if err != nil {
			t.Fatalf("installed client key missing: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("installed key mode want 0600, got %o", info.Mode().Perm())
		}
		adminBytes, err := os.ReadFile(adminKeyPath)
		if err != nil {
			t.Fatalf("read admin key: %v", err)
		}
		clientBytes, err := os.ReadFile(clientKeyPath)
		if err != nil {
			t.Fatalf("read client key: %v", err)
		}
		if string(adminBytes) != string(clientBytes) {
			t.Fatalf("installed file does not match admin source byte-for-byte")
		}
	}

	if err := runLeakScan(t, filepath.Join(adminKauket, "repo")); err != nil {
		t.Fatalf("leak scan: %v", err)
	}
}

func ghAuthAsOwner(t *testing.T, owner string) error {
	t.Helper()
	if _, err := exec.LookPath("gh"); err != nil {
		return fmt.Errorf("gh not on PATH: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "gh", "auth", "status").CombinedOutput()
	if err != nil {
		return fmt.Errorf("gh auth status failed: %w\n%s", err, string(out))
	}
	combined := string(out)
	needle := "account " + owner
	if !strings.Contains(combined, needle) {
		return fmt.Errorf("gh auth status output does not mention account %q\n%s", owner, combined)
	}
	return nil
}

func ghRepoViewJSON(t *testing.T, slug string) (*ghRepoView, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "gh", "repo", "view", slug, "--json", "name,private").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("gh repo view %s: %w\n%s", slug, err, string(out))
	}
	var v ghRepoView
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, fmt.Errorf("parse gh repo view output: %w\n%s", err, string(out))
	}
	return &v, nil
}

func ghListDeployKeys(t *testing.T, slug string) ([]ghDeployKey, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpoint := fmt.Sprintf("/repos/%s/keys", slug)
	out, err := exec.CommandContext(ctx, "gh", "api", endpoint).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("gh api %s: %w\n%s", endpoint, err, string(out))
	}
	var keys []ghDeployKey
	if err := json.Unmarshal(out, &keys); err != nil {
		return nil, fmt.Errorf("parse gh api keys output: %w\n%s", err, string(out))
	}
	return keys, nil
}

func runLeakScan(t *testing.T, scanDir string) error {
	t.Helper()
	root, err := repoRoot()
	if err != nil {
		return err
	}
	script := filepath.Join(root, "scripts", "leak-scan.sh")
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("leak-scan.sh not found at %s: %w", script, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, script, scanDir).CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("leak-scan reported hits (exit %d):\n%s", exitErr.ExitCode(), string(out))
		}
		return fmt.Errorf("leak-scan failed: %w\n%s", err, string(out))
	}
	return nil
}

func randomEnrollName() string {
	return fmt.Sprintf("e2e-host-%d", time.Now().UnixNano())
}
