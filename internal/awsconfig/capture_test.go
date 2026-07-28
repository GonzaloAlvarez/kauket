package awsconfig

import (
	"strings"
	"testing"
)

const captureConfig = `# global comment
[default]
region = us-east-1

[profile amzn-wanfe]
region = us-west-2
sso_session = amzn
output = json

[sso-session amzn]
sso_start_url = https://amzn.awsapps.com/start
sso_region = us-east-1

[profile chained]
role_arn = arn:aws:iam::123:role/x
source_profile = amzn-wanfe

[profile dangling-sso]
sso_session = missing
`

const captureCreds = `[amzn-wanfe]
aws_access_key_id = AKIAEXAMPLE
aws_secret_access_key = secretvalue

[credsonly]
aws_access_key_id = AKIAOTHER
aws_secret_access_key = othersecret
`

func TestCaptureProfileBothFiles(t *testing.T) {
	got, err := CaptureProfile("amzn-wanfe", []byte(captureConfig), []byte(captureCreds), "/a/config", "/a/credentials")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	wantConfig := "[profile amzn-wanfe]\nregion = us-west-2\nsso_session = amzn\noutput = json\n\n[sso-session amzn]\nsso_start_url = https://amzn.awsapps.com/start\nsso_region = us-east-1\n"
	if got.Envelope.Config != wantConfig {
		t.Fatalf("config:\n got %q\nwant %q", got.Envelope.Config, wantConfig)
	}
	wantCreds := "[amzn-wanfe]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = secretvalue\n"
	if got.Envelope.Credentials != wantCreds {
		t.Fatalf("credentials:\n got %q\nwant %q", got.Envelope.Credentials, wantCreds)
	}
	wantCaptured := []string{
		"captured [profile amzn-wanfe] from /a/config",
		"captured [sso-session amzn] from /a/config",
		"captured [amzn-wanfe] from /a/credentials",
	}
	if len(got.Captured) != len(wantCaptured) {
		t.Fatalf("captured = %v", got.Captured)
	}
	for i, w := range wantCaptured {
		if got.Captured[i] != w {
			t.Fatalf("captured[%d] = %q, want %q", i, got.Captured[i], w)
		}
	}
	if len(got.Warnings) != 0 {
		t.Fatalf("warnings = %v", got.Warnings)
	}
	if got.Envelope.Profile != "amzn-wanfe" || got.Envelope.Schema != EnvelopeSchema {
		t.Fatalf("envelope meta = %+v", got.Envelope)
	}
}

func TestCaptureProfileConfigOnly(t *testing.T) {
	got, err := CaptureProfile("dangling-sso", []byte(captureConfig), []byte(captureCreds), "/a/config", "/a/credentials")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if got.Envelope.Credentials != "" {
		t.Fatalf("credentials should be empty, got %q", got.Envelope.Credentials)
	}
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], `sso_session "missing"`) {
		t.Fatalf("warnings = %v", got.Warnings)
	}
}

func TestCaptureProfileCredsOnly(t *testing.T) {
	got, err := CaptureProfile("credsonly", []byte(captureConfig), []byte(captureCreds), "/a/config", "/a/credentials")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if got.Envelope.Config != "" {
		t.Fatalf("config should be empty, got %q", got.Envelope.Config)
	}
	if !strings.Contains(got.Envelope.Credentials, "AKIAOTHER") {
		t.Fatalf("credentials = %q", got.Envelope.Credentials)
	}
	if len(got.Captured) != 1 {
		t.Fatalf("captured = %v", got.Captured)
	}
}

func TestCaptureProfileNotFound(t *testing.T) {
	_, err := CaptureProfile("nope", []byte(captureConfig), []byte(captureCreds), "/a/config", "/a/credentials")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "/a/config") || !strings.Contains(err.Error(), "/a/credentials") {
		t.Fatalf("error should name both paths: %v", err)
	}
}

func TestCaptureProfileDefault(t *testing.T) {
	for _, header := range []string{"[default]", "[profile default]"} {
		cfg := header + "\nregion = us-east-1\n"
		got, err := CaptureProfile("default", []byte(cfg), nil, "/a/config", "/a/credentials")
		if err != nil {
			t.Fatalf("capture %s: %v", header, err)
		}
		if !strings.Contains(got.Envelope.Config, "region = us-east-1") {
			t.Fatalf("config = %q", got.Envelope.Config)
		}
	}
}

func TestCaptureProfileSourceProfileWarns(t *testing.T) {
	got, err := CaptureProfile("chained", []byte(captureConfig), nil, "/a/config", "/a/credentials")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], `source_profile "amzn-wanfe"`) {
		t.Fatalf("warnings = %v", got.Warnings)
	}
}

func TestCaptureProfileFirstDuplicateWins(t *testing.T) {
	cfg := "[profile dup]\nfirst = 1\n\n[profile dup]\nsecond = 2\n"
	got, err := CaptureProfile("dup", []byte(cfg), nil, "/a/config", "/a/credentials")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if !strings.Contains(got.Envelope.Config, "first = 1") || strings.Contains(got.Envelope.Config, "second = 2") {
		t.Fatalf("config = %q", got.Envelope.Config)
	}
}

func TestReadFilesHonorsEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", dir+"/cfg")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", dir+"/creds")
	configText, credsText, configPath, credsPath, err := ReadFiles()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if configPath != dir+"/cfg" || credsPath != dir+"/creds" {
		t.Fatalf("paths = %q %q", configPath, credsPath)
	}
	if configText != nil || credsText != nil {
		t.Fatalf("missing files should read as nil")
	}
}
