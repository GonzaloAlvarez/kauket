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
	"github.com/gonzaloalvarez/kauket/internal/model"
)

const (
	awsCliConfigSection = "[profile amzn-wanfe]\nregion = us-west-2\nsso_session = amzn\n\n[sso-session amzn]\nsso_start_url = https://amzn.awsapps.com/start\n"
	awsCliCredsSection  = "[amzn-wanfe]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = secretvalue\n"
)

func awsCliEnvelope(t *testing.T) []byte {
	t.Helper()
	data, err := awsconfig.Envelope{
		Schema:      awsconfig.EnvelopeSchema,
		Profile:     "amzn-wanfe",
		Config:      awsCliConfigSection,
		Credentials: awsCliCredsSection,
	}.Marshal()
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return data
}

func setupClientWithAWSBundle(t *testing.T, envelope []byte, kind string) *clientFixture {
	t.Helper()
	fx, hostIdentity, adminIdentity := setupClient(t)
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	secrets := map[string]model.BundleSecret{
		"aws.profile.amzn-wanfe": {
			Kind:          kind,
			ContentBase64: base64.StdEncoding.EncodeToString(envelope),
			SHA256:        "deadbeef",
		},
	}
	ct := encryptBundleFor(t, fx, hostIdentity, adminIdentity, secrets)
	writeLocalBundle(t, fx.home, fx.hostID, ct)
	return fx
}

func TestGetAWSProfileMergesAlongsideExisting(t *testing.T) {
	fx := setupClientWithAWSBundle(t, awsCliEnvelope(t), "aws_profile")
	awsDir := filepath.Join(fx.tempHome, ".aws")
	if err := os.MkdirAll(awsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	existing := "[profile personal]\nregion = us-east-1\n"
	if err := os.WriteFile(filepath.Join(awsDir, "config"), []byte(existing), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	flags := &getFlags{noSync: true}
	if err := runGet(context.Background(), fx.app, flags, "aws.profile.amzn-wanfe"); err != nil {
		t.Fatalf("runGet: %v", err)
	}
	wantLines := []string{"updating ~/.aws/config", "creating ~/.aws/credentials"}
	if len(fx.fake.Lines) != len(wantLines) {
		t.Fatalf("lines = %v", fx.fake.Lines)
	}
	for i, w := range wantLines {
		if fx.fake.Lines[i] != w {
			t.Fatalf("line %d = %q, want %q", i, fx.fake.Lines[i], w)
		}
	}

	cfg, err := os.ReadFile(filepath.Join(awsDir, "config"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.HasPrefix(string(cfg), existing) {
		t.Fatalf("existing profile not preserved: %q", cfg)
	}
	if !strings.Contains(string(cfg), "[profile amzn-wanfe]") || !strings.Contains(string(cfg), "[sso-session amzn]") {
		t.Fatalf("merged sections missing: %q", cfg)
	}
	creds, err := os.ReadFile(filepath.Join(awsDir, "credentials"))
	if err != nil {
		t.Fatalf("read credentials: %v", err)
	}
	if string(creds) != awsCliCredsSection {
		t.Fatalf("credentials = %q", creds)
	}
}

func TestGetAWSProfileAlreadyCurrent(t *testing.T) {
	fx := setupClientWithAWSBundle(t, awsCliEnvelope(t), "aws_profile")
	flags := &getFlags{noSync: true}
	if err := runGet(context.Background(), fx.app, flags, "aws.profile.amzn-wanfe"); err != nil {
		t.Fatalf("first runGet: %v", err)
	}
	fx.fake.Lines = nil
	if err := runGet(context.Background(), fx.app, flags, "aws.profile.amzn-wanfe"); err != nil {
		t.Fatalf("second runGet: %v", err)
	}
	if len(fx.fake.Lines) != 1 || fx.fake.Lines[0] != "profile amzn-wanfe already current" {
		t.Fatalf("lines = %v", fx.fake.Lines)
	}
}

func TestGetAWSProfileStdout(t *testing.T) {
	envelope := awsCliEnvelope(t)
	fx := setupClientWithAWSBundle(t, envelope, "aws_profile")
	flags := &getFlags{noSync: true, stdout: true}
	out := captureStdout(t, func() {
		if err := runGet(context.Background(), fx.app, flags, "aws.profile.amzn-wanfe"); err != nil {
			t.Fatalf("runGet: %v", err)
		}
	})
	if string(out) != string(envelope) {
		t.Fatalf("stdout = %q, want envelope", out)
	}
	if _, err := os.Stat(filepath.Join(fx.tempHome, ".aws")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stdout mode should not touch ~/.aws; stat err = %v", err)
	}
}

func TestGetUnsupportedKind(t *testing.T) {
	fx := setupClientWithAWSBundle(t, awsCliEnvelope(t), "pkcs11")
	flags := &getFlags{noSync: true}
	err := runGet(context.Background(), fx.app, flags, "aws.profile.amzn-wanfe")
	if err == nil {
		t.Fatalf("expected error for unsupported kind")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitInstall {
		t.Fatalf("err = %v, want ExitInstall", err)
	}
	if !strings.Contains(err.Error(), `unsupported kind "pkcs11"`) {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestGetAWSProfileUnmanagedSection(t *testing.T) {
	fx := setupClientWithAWSBundle(t, awsCliEnvelope(t), "aws_profile")
	awsDir := filepath.Join(fx.tempHome, ".aws")
	if err := os.MkdirAll(awsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(awsDir, "credentials"), []byte("[amzn-wanfe]\naws_access_key_id = HANDEDITED\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	flags := &getFlags{noSync: true}
	err := runGet(context.Background(), fx.app, flags, "aws.profile.amzn-wanfe")
	if err == nil {
		t.Fatalf("expected unmanaged section error")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitInstall {
		t.Fatalf("err = %v, want ExitInstall", err)
	}
	if !strings.Contains(err.Error(), "use --force or --backup") {
		t.Fatalf("error = %q", err.Error())
	}

	fx.fake.Lines = nil
	if err := runGet(context.Background(), fx.app, &getFlags{noSync: true, force: true}, "aws.profile.amzn-wanfe"); err != nil {
		t.Fatalf("forced runGet: %v", err)
	}
	creds, err := os.ReadFile(filepath.Join(awsDir, "credentials"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(creds) != awsCliCredsSection {
		t.Fatalf("credentials = %q", creds)
	}
}
