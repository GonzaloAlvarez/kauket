//go:build e2e

package e2e_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type migClient struct {
	name     string
	home     string
	kauket   string
	profiles []string
	granted  []string
	denied   []string
}

func TestMigrateStoreLocalE2E(t *testing.T) {
	bin := buildBinary(t)
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")

	root := mustResolvedTempRoot(t)
	adminHome := filepath.Join(root, "admin-home")
	adminKauket := filepath.Join(adminHome, ".config", "kauket")
	bareDir := filepath.Join(root, "bare-remote.git")
	mustMkdir(t, filepath.Join(adminHome, ".aws"), 0o700)
	remoteURL := setupBareRemote(t, bareDir)

	res := runKauket(t, bin, adminKauket, adminHome, "init", "--remote", remoteURL, "--no-github", "--yes")
	if res.err != nil {
		t.Fatalf("init: %v\nstderr:%s", res.err, res.stderr)
	}

	sources := map[string]string{}
	addSecret := func(id, content string, extra ...string) {
		p := filepath.Join(adminHome, "src", strings.ReplaceAll(id, ".", "_"))
		mustMkdir(t, filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write source: %v", err)
		}
		sources[id] = content
		args := append([]string{"add", id, p}, extra...)
		res := runKauket(t, bin, adminKauket, adminHome, args...)
		if res.err != nil {
			t.Fatalf("add %s: %v\nstderr:%s", id, res.err, res.stderr)
		}
	}
	addSecret("ssh.main_private_key", "SSH MAIN KEY CONTENT")
	addSecret("ssh.backup_private_key", "SSH BACKUP KEY CONTENT")
	addSecret("infra.k8s.admin_kubeconfig", "KUBECONFIG CONTENT", "--dest", "~/.kube/config", "--profile", "infra")
	addSecret("binary.blob", "BINARY BLOB CONTENT", "--dest", "~/.local/share/blob", "--profile", "test")

	awsConfig := "[profile amzn-wanfe]\nregion = us-west-2\n"
	awsCreds := "[amzn-wanfe]\naws_access_key_id = AKIAMIG\naws_secret_access_key = migsecret\n"
	if err := os.WriteFile(filepath.Join(adminHome, ".aws", "config"), []byte(awsConfig), 0o600); err != nil {
		t.Fatalf("aws config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(adminHome, ".aws", "credentials"), []byte(awsCreds), 0o600); err != nil {
		t.Fatalf("aws credentials: %v", err)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "add", "--aws-profile", "amzn-wanfe")
	if res.err != nil {
		t.Fatalf("add aws profile: %v\nstderr:%s", res.err, res.stderr)
	}

	clients := []*migClient{
		{name: "m-ssh", profiles: []string{"ssh"},
			granted: []string{"ssh.main_private_key", "ssh.backup_private_key"},
			denied:  []string{"infra.k8s.admin_kubeconfig", "aws.profile.amzn-wanfe"}},
		{name: "m-mixed", profiles: []string{"aws", "infra"},
			granted: []string{"aws.profile.amzn-wanfe", "infra.k8s.admin_kubeconfig"},
			denied:  []string{"ssh.main_private_key", "binary.blob"}},
		{name: "m-test", profiles: []string{"ssh", "test"},
			granted: []string{"ssh.main_private_key", "ssh.backup_private_key", "binary.blob"},
			denied:  []string{"aws.profile.amzn-wanfe"}},
	}
	for _, c := range clients {
		c.home = filepath.Join(root, c.name+"-home")
		c.kauket = filepath.Join(c.home, ".config", "kauket")
		mustMkdir(t, c.home, 0o700)
		args := []string{"enroll", "--remote", remoteURL, "--name", c.name, "--yes"}
		for _, p := range c.profiles {
			args = append(args, "--request", p)
		}
		res := runKauket(t, bin, c.kauket, c.home, args...)
		if res.err != nil {
			t.Fatalf("enroll %s: %v\nstderr:%s", c.name, res.err, res.stderr)
		}
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
	if !strings.Contains(res.stdout, "migrated store") || !strings.Contains(res.stdout, "OFFLINE") {
		t.Fatalf("migrate output: %q", res.stdout)
	}

	adminRepo := filepath.Join(roleHomePath(adminKauket, "admin"), "repo")
	for _, p := range []string{"repo.json", "admin/vault.age"} {
		if _, err := os.Stat(filepath.Join(adminRepo, p)); err != nil {
			t.Fatalf("frozen v1 file missing after migration: %v", err)
		}
	}

	res = runKauket(t, bin, adminKauket, adminHome, "verify")
	if res.err != nil {
		t.Fatalf("admin verify: %v\nstderr:%s", res.err, res.stderr)
	}

	for _, c := range clients {
		for _, id := range c.granted {
			res := runKauket(t, bin, c.kauket, c.home, "get", id, "--stdout")
			if res.err != nil {
				t.Fatalf("%s get %s: %v\nstderr:%s", c.name, id, res.err, res.stderr)
			}
			if id == "aws.profile.amzn-wanfe" {
				if !strings.Contains(res.stdout, "amzn-wanfe") {
					t.Fatalf("%s get %s: envelope missing profile name", c.name, id)
				}
				continue
			}
			if res.stdout != sources[id] {
				t.Fatalf("%s get %s: content mismatch\n got %q\nwant %q", c.name, id, res.stdout, sources[id])
			}
		}
		for _, id := range c.denied {
			res := runKauket(t, bin, c.kauket, c.home, "get", id, "--stdout", "--no-sync")
			if res.err == nil {
				t.Fatalf("%s get %s should fail", c.name, id)
			}
			if code := exitCodeOf(res.err); code != 5 {
				t.Fatalf("%s get %s exit = %d, want 5; stderr:%s", c.name, id, code, res.stderr)
			}
		}
		res := runKauket(t, bin, c.kauket, c.home, "verify", "--no-sync")
		if res.err != nil {
			t.Fatalf("%s verify: %v\nstderr:%s", c.name, res.err, res.stderr)
		}
	}

	forbidden := []string{"ssh.main_private_key", "amzn-wanfe", "AKIAMIG", "migsecret", "kubeconfig", "m-mixed"}
	for _, term := range forbidden {
		if hits := grepRepo(t, adminRepo, term); len(hits) != 0 {
			t.Fatalf("leak: term %q found in migrated repo: %v", term, hits)
		}
	}
}

func TestV2InitLocalE2E(t *testing.T) {
	bin := buildBinary(t)
	root := mustResolvedTempRoot(t)
	home := filepath.Join(root, "founder-home")
	kauketHome := filepath.Join(home, ".config", "kauket")
	bareDir := filepath.Join(root, "bare-remote.git")
	mustMkdir(t, home, 0o700)
	remoteURL := setupBareRemote(t, bareDir)
	recoveryOut := filepath.Join(root, "recovery")

	res := runKauket(t, bin, kauketHome, home, "init", "--v2", "--recovery-out", recoveryOut, "--remote", remoteURL, "--no-github", "--yes")
	if res.err != nil {
		t.Fatalf("init --v2: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "initialized kauket v2 store") || !strings.Contains(res.stdout, "OFFLINE") {
		t.Fatalf("init output: %q", res.stdout)
	}

	res = runKauket(t, bin, kauketHome, home, "verify")
	if res.err != nil {
		t.Fatalf("verify: %v\nstderr:%s", res.err, res.stderr)
	}
	if !strings.Contains(res.stdout, "verified 1 nodes, 0 entries") {
		t.Fatalf("verify output: %q", res.stdout)
	}

	res = runKauket(t, bin, kauketHome, home, "status")
	if res.err != nil {
		t.Fatalf("status: %v\nstderr:%s", res.err, res.stderr)
	}
	if !strings.Contains(res.stdout, "schema: 2") {
		t.Fatalf("status output: %q", res.stdout)
	}
}
