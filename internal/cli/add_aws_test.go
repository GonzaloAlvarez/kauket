package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gonzaloalvarez/kauket/internal/awsconfig"
)

func writeAWSFixture(t *testing.T, config, creds string) string {
	t.Helper()
	tempHome := t.TempDir()
	resolved, err := filepath.EvalSymlinks(tempHome)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	tempHome = resolved
	t.Setenv("HOME", tempHome)
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	awsDir := filepath.Join(tempHome, ".aws")
	if err := os.MkdirAll(awsDir, 0o700); err != nil {
		t.Fatalf("mkdir aws dir: %v", err)
	}
	if config != "" {
		if err := os.WriteFile(filepath.Join(awsDir, "config"), []byte(config), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
	}
	if creds != "" {
		if err := os.WriteFile(filepath.Join(awsDir, "credentials"), []byte(creds), 0o600); err != nil {
			t.Fatalf("write credentials: %v", err)
		}
	}
	return tempHome
}

func TestAddAWSProfileCapturesIntoVault(t *testing.T) {
	a, fake, home := initAdminFixture(t)
	tempHome := writeAWSFixture(t, awsCliConfigSection, awsCliCredsSection)

	if err := runAdd(context.Background(), a, &addFlags{awsProfile: "amzn-wanfe"}, "", ""); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	awsDir := filepath.Join(tempHome, ".aws")
	wantLines := []string{
		"captured [profile amzn-wanfe] from " + filepath.Join(awsDir, "config"),
		"captured [sso-session amzn] from " + filepath.Join(awsDir, "config"),
		"captured [amzn-wanfe] from " + filepath.Join(awsDir, "credentials"),
		"added aws.profile.amzn-wanfe",
		"updated 0 host bundles",
	}
	if len(fake.Lines) != len(wantLines) {
		t.Fatalf("lines = %v", fake.Lines)
	}
	for i, w := range wantLines {
		if fake.Lines[i] != w {
			t.Fatalf("line %d = %q, want %q", i, fake.Lines[i], w)
		}
	}

	v := loadAdminVault(t, home)
	secret, ok := v.Secrets["aws.profile.amzn-wanfe"]
	if !ok {
		t.Fatalf("secret missing from vault")
	}
	if secret.Kind != "aws_profile" {
		t.Fatalf("kind = %q", secret.Kind)
	}
	if secret.Install.Destination != "" || secret.Install.Mode != "" || secret.Install.DirectoryMode != "" {
		t.Fatalf("install spec should be empty: %+v", secret.Install)
	}
	if len(secret.Profiles) != 1 || secret.Profiles[0] != "aws" {
		t.Fatalf("profiles = %v", secret.Profiles)
	}
	raw, err := base64.StdEncoding.DecodeString(secret.ContentBase64)
	if err != nil {
		t.Fatalf("decode content: %v", err)
	}
	env, err := awsconfig.ParseEnvelope(raw)
	if err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	if env.Profile != "amzn-wanfe" {
		t.Fatalf("envelope profile = %q", env.Profile)
	}
	if !strings.Contains(env.Config, "[sso-session amzn]") {
		t.Fatalf("envelope config = %q", env.Config)
	}
	if env.Credentials != awsCliCredsSection {
		t.Fatalf("envelope credentials = %q", env.Credentials)
	}
}

func TestAddAWSProfileSourceProfileWarns(t *testing.T) {
	a, fake, _ := initAdminFixture(t)
	writeAWSFixture(t, "[profile chained]\nrole_arn = arn:aws:iam::123:role/x\nsource_profile = base\n", "")

	if err := runAdd(context.Background(), a, &addFlags{awsProfile: "chained"}, "", ""); err != nil {
		t.Fatalf("runAdd: %v", err)
	}
	foundWarning := false
	for _, line := range fake.Lines {
		if strings.HasPrefix(line, "warning: ") && strings.Contains(line, `source_profile "base"`) {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Fatalf("expected source_profile warning, lines = %v", fake.Lines)
	}
}

func TestAddAWSProfileNotFound(t *testing.T) {
	a, _, _ := initAdminFixture(t)
	tempHome := writeAWSFixture(t, "[profile other]\nregion = us-east-1\n", "")

	err := runAdd(context.Background(), a, &addFlags{awsProfile: "nope"}, "", "")
	if err == nil {
		t.Fatalf("expected error")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitUsage {
		t.Fatalf("err = %v, want ExitUsage", err)
	}
	awsDir := filepath.Join(tempHome, ".aws")
	if !strings.Contains(err.Error(), filepath.Join(awsDir, "config")) || !strings.Contains(err.Error(), filepath.Join(awsDir, "credentials")) {
		t.Fatalf("error should name both paths: %v", err)
	}
}

func TestAddAWSProfileRejectsPositionalArgs(t *testing.T) {
	a, _, _ := initAdminFixture(t)
	err := runAdd(context.Background(), a, &addFlags{awsProfile: "x"}, "some.id", "")
	if err == nil || !strings.Contains(err.Error(), "no positional arguments") {
		t.Fatalf("err = %v", err)
	}
}

func TestAddAWSProfileRejectsInstallFlags(t *testing.T) {
	a, _, _ := initAdminFixture(t)
	err := runAdd(context.Background(), a, &addFlags{awsProfile: "x", dest: "/etc/foo"}, "", "")
	if err == nil || !strings.Contains(err.Error(), "cannot be used with --aws-profile") {
		t.Fatalf("err = %v", err)
	}
}

func TestAddRequiresArgsWithoutAWSProfile(t *testing.T) {
	a, _, _ := initAdminFixture(t)
	err := runAdd(context.Background(), a, &addFlags{}, "", "")
	if err == nil {
		t.Fatalf("expected error")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitUsage {
		t.Fatalf("err = %v, want ExitUsage", err)
	}
	if !strings.Contains(err.Error(), "--aws-profile") {
		t.Fatalf("error should mention --aws-profile alternative: %v", err)
	}
}

func TestAddAWSProfileInvalidName(t *testing.T) {
	a, _, _ := initAdminFixture(t)
	err := runAdd(context.Background(), a, &addFlags{awsProfile: "Foo"}, "", "")
	if err == nil || !strings.Contains(err.Error(), "cannot be encoded as a secret id") {
		t.Fatalf("err = %v", err)
	}
}

func TestAddAWSProfileRequiresForceToReplace(t *testing.T) {
	a, fake, _ := initAdminFixture(t)
	writeAWSFixture(t, awsCliConfigSection, awsCliCredsSection)

	if err := runAdd(context.Background(), a, &addFlags{awsProfile: "amzn-wanfe"}, "", ""); err != nil {
		t.Fatalf("first add: %v", err)
	}
	fake.Lines = nil

	err := runAdd(context.Background(), a, &addFlags{awsProfile: "amzn-wanfe"}, "", "")
	if err == nil || !strings.Contains(err.Error(), "force") {
		t.Fatalf("second add err = %v, want force hint", err)
	}

	fake.Lines = nil
	if err := runAdd(context.Background(), a, &addFlags{awsProfile: "amzn-wanfe", force: true}, "", ""); err != nil {
		t.Fatalf("forced add: %v", err)
	}
	foundUpdated := false
	for _, line := range fake.Lines {
		if line == "updated aws.profile.amzn-wanfe" {
			foundUpdated = true
			break
		}
	}
	if !foundUpdated {
		t.Fatalf("expected updated line, got %v", fake.Lines)
	}
}

func TestAddAWSProfileEnvOverride(t *testing.T) {
	a, fake, _ := initAdminFixture(t)
	writeAWSFixture(t, "", "")
	altConfig := filepath.Join(t.TempDir(), "custom-aws-config")
	if err := os.WriteFile(altConfig, []byte("[profile amzn-wanfe]\nregion = eu-central-1\n"), 0o600); err != nil {
		t.Fatalf("write alt config: %v", err)
	}
	t.Setenv("AWS_CONFIG_FILE", altConfig)

	if err := runAdd(context.Background(), a, &addFlags{awsProfile: "amzn-wanfe"}, "", ""); err != nil {
		t.Fatalf("runAdd: %v", err)
	}
	if len(fake.Lines) == 0 || fake.Lines[0] != "captured [profile amzn-wanfe] from "+altConfig {
		t.Fatalf("lines = %v", fake.Lines)
	}
}
