//go:build e2e

package e2e_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	e2eAWSConfig = `[profile amzn-wanfe]
region = us-west-2
sso_session = amzn
output = json

[sso-session amzn]
sso_start_url = https://amzn.awsapps.com/start
sso_region = us-east-1

[profile other]
region = eu-west-1
`
	e2eAWSCreds = `[amzn-wanfe]
aws_access_key_id = AKIAE2EEXAMPLE
aws_secret_access_key = e2esecretvalue
`
	e2eClientAWSConfig = `# client-managed
[profile personal]
region = ap-southeast-2
`
	e2eClientAWSCreds = `[personal]
aws_access_key_id = AKIACLIENTLOCAL
aws_secret_access_key = clientlocalsecret
`
)

func TestAWSProfileLocalE2E(t *testing.T) {
	bin := buildBinary(t)
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")

	root := mustResolvedTempRoot(t)
	adminHome := filepath.Join(root, "admin-home")
	adminKauket := filepath.Join(adminHome, ".config", "kauket")
	clientHome := filepath.Join(root, "machine2-home")
	clientKauket := filepath.Join(clientHome, ".config", "kauket")
	bareDir := filepath.Join(root, "bare-remote.git")
	mustMkdir(t, filepath.Join(adminHome, ".aws"), 0o700)
	mustMkdir(t, filepath.Join(clientHome, ".aws"), 0o700)
	remoteURL := setupBareRemote(t, bareDir)

	if err := os.WriteFile(filepath.Join(adminHome, ".aws", "config"), []byte(e2eAWSConfig), 0o600); err != nil {
		t.Fatalf("write admin aws config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(adminHome, ".aws", "credentials"), []byte(e2eAWSCreds), 0o600); err != nil {
		t.Fatalf("write admin aws credentials: %v", err)
	}
	if err := os.WriteFile(filepath.Join(clientHome, ".aws", "config"), []byte(e2eClientAWSConfig), 0o600); err != nil {
		t.Fatalf("write client aws config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(clientHome, ".aws", "credentials"), []byte(e2eClientAWSCreds), 0o600); err != nil {
		t.Fatalf("write client aws credentials: %v", err)
	}

	res := runKauket(t, bin, adminKauket, adminHome, "init", "--remote", remoteURL, "--recovery-out", filepath.Join(root, "recovery"), "--yes")
	if res.err != nil {
		t.Fatalf("init: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, adminKauket, adminHome, "add", "--aws-profile", "amzn-wanfe")
	if res.err != nil {
		t.Fatalf("add --aws-profile: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	for _, want := range []string{
		"captured [profile amzn-wanfe] from",
		"captured [sso-session amzn] from",
		"captured [amzn-wanfe] from",
		"added aws.profile.amzn-wanfe",
	} {
		if !strings.Contains(res.stdout, want) {
			t.Fatalf("add stdout missing %q: %q", want, res.stdout)
		}
	}

	res = runKauket(t, bin, clientKauket, clientHome, "request", "aws/profile", "--remote", remoteURL, "--name", "machine2", "--yes")
	if res.err != nil {
		t.Fatalf("enroll: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	res = runKauket(t, bin, adminKauket, adminHome, "approve", "--all", "--yes")
	if res.err != nil {
		t.Fatalf("approve: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "get", "aws.profile.amzn-wanfe")
	if res.err != nil {
		t.Fatalf("get: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "updating ~/.aws/config") || !strings.Contains(res.stdout, "updating ~/.aws/credentials") {
		t.Fatalf("get stdout: %q", res.stdout)
	}

	cfg, err := os.ReadFile(filepath.Join(clientHome, ".aws", "config"))
	if err != nil {
		t.Fatalf("read client config: %v", err)
	}
	if !strings.HasPrefix(string(cfg), e2eClientAWSConfig) {
		t.Fatalf("client's own config not preserved: %q", cfg)
	}
	if !strings.Contains(string(cfg), "[profile amzn-wanfe]") || !strings.Contains(string(cfg), "[sso-session amzn]") {
		t.Fatalf("merged sections missing: %q", cfg)
	}
	if strings.Contains(string(cfg), "[profile other]") {
		t.Fatalf("uncaptured admin profile leaked to client: %q", cfg)
	}
	creds, err := os.ReadFile(filepath.Join(clientHome, ".aws", "credentials"))
	if err != nil {
		t.Fatalf("read client credentials: %v", err)
	}
	if !strings.HasPrefix(string(creds), e2eClientAWSCreds) {
		t.Fatalf("client's own credentials not preserved: %q", creds)
	}
	if !strings.Contains(string(creds), "aws_access_key_id = AKIAE2EEXAMPLE") {
		t.Fatalf("merged credentials missing: %q", creds)
	}

	res = runKauket(t, bin, clientKauket, clientHome, "get", "aws.profile.amzn-wanfe")
	if res.err != nil {
		t.Fatalf("second get: %v\nstdout:%s\nstderr:%s", res.err, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "profile amzn-wanfe already current") {
		t.Fatalf("second get stdout: %q", res.stdout)
	}

	adminRepo := filepath.Join(roleHomePath(adminKauket, "admin"), "repo")
	for _, term := range []string{"amzn-wanfe", "AKIAE2EEXAMPLE", "e2esecretvalue", "sso_start_url"} {
		if hits := grepRepo(t, adminRepo, term); len(hits) != 0 {
			t.Fatalf("leak: term %q found in admin repo: %v", term, hits)
		}
	}
}
