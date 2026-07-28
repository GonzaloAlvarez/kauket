package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gonzaloalvarez/kauket/internal/awsconfig"
)

const (
	awsTestConfigSection = "[profile amzn-wanfe]\nregion = us-west-2\nsso_session = amzn\n\n[sso-session amzn]\nsso_start_url = https://amzn.awsapps.com/start\n"
	awsTestCredsSection  = "[amzn-wanfe]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = secretvalue\n"
)

func awsEnvelope(t *testing.T, profile, config, creds string) []byte {
	t.Helper()
	data, err := awsconfig.Envelope{Schema: awsconfig.EnvelopeSchema, Profile: profile, Config: config, Credentials: creds}.Marshal()
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return data
}

func awsTestOptions(t *testing.T) (Options, string) {
	t.Helper()
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	kauketHome := filepath.Join(tempHome, ".config", "kauket")
	return Options{
		Home: kauketHome,
		Now:  fixedClock(time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC)),
	}, tempHome
}

func TestInstallAWSProfileFresh(t *testing.T) {
	opts, tempHome := awsTestOptions(t)
	content := awsEnvelope(t, "amzn-wanfe", awsTestConfigSection, awsTestCredsSection)

	res, err := InstallAWSProfile("aws.profile.amzn-wanfe", content, opts)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Profile != "amzn-wanfe" {
		t.Fatalf("profile = %q", res.Profile)
	}
	if len(res.Files) != 2 || res.Files[0].Status != StatusCreated || res.Files[1].Status != StatusCreated {
		t.Fatalf("files = %+v", res.Files)
	}
	if res.Files[0].Destination != "~/.aws/config" || res.Files[1].Destination != "~/.aws/credentials" {
		t.Fatalf("destinations = %+v", res.Files)
	}

	cfg, err := os.ReadFile(filepath.Join(tempHome, ".aws", "config"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(cfg) != awsTestConfigSection {
		t.Fatalf("config = %q", cfg)
	}
	creds, err := os.ReadFile(filepath.Join(tempHome, ".aws", "credentials"))
	if err != nil {
		t.Fatalf("read credentials: %v", err)
	}
	if string(creds) != awsTestCredsSection {
		t.Fatalf("credentials = %q", creds)
	}

	dirInfo, err := os.Stat(filepath.Join(tempHome, ".aws"))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %o", dirInfo.Mode().Perm())
	}
	for _, f := range []string{"config", "credentials"} {
		info, err := os.Stat(filepath.Join(tempHome, ".aws", f))
		if err != nil {
			t.Fatalf("stat %s: %v", f, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o", f, info.Mode().Perm())
		}
	}

	state, err := LoadState(opts.Home)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	entry, ok := state.Installed["aws.profile.amzn-wanfe"]
	if !ok {
		t.Fatalf("state entry missing")
	}
	if entry.Destination != "~/.aws/config, ~/.aws/credentials" {
		t.Fatalf("entry destination = %q", entry.Destination)
	}
	for _, key := range []string{"config|amzn-wanfe", "config|sso-session amzn", "credentials|amzn-wanfe"} {
		if entry.Sections[key] == "" {
			t.Fatalf("state sections missing %q: %v", key, entry.Sections)
		}
	}
}

func TestInstallAWSProfilePreservesUnrelatedAndMode(t *testing.T) {
	opts, tempHome := awsTestOptions(t)
	awsDir := filepath.Join(tempHome, ".aws")
	if err := os.MkdirAll(awsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	existing := "# my config\n[profile personal]\nregion = us-east-1\n"
	if err := os.WriteFile(filepath.Join(awsDir, "config"), []byte(existing), 0o644); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	content := awsEnvelope(t, "amzn-wanfe", awsTestConfigSection, awsTestCredsSection)
	res, err := InstallAWSProfile("aws.profile.amzn-wanfe", content, opts)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Files[0].Status != StatusReplaced {
		t.Fatalf("config status = %v, want StatusReplaced", res.Files[0].Status)
	}

	cfg, err := os.ReadFile(filepath.Join(awsDir, "config"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.HasPrefix(string(cfg), existing) {
		t.Fatalf("existing content not preserved: %q", cfg)
	}
	if !strings.Contains(string(cfg), "[profile amzn-wanfe]") {
		t.Fatalf("merged section missing: %q", cfg)
	}
	info, err := os.Stat(filepath.Join(awsDir, "config"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %o, want preserved 0644", info.Mode().Perm())
	}
}

func TestInstallAWSProfileNoChange(t *testing.T) {
	opts, tempHome := awsTestOptions(t)
	content := awsEnvelope(t, "amzn-wanfe", awsTestConfigSection, awsTestCredsSection)
	if _, err := InstallAWSProfile("aws.profile.amzn-wanfe", content, opts); err != nil {
		t.Fatalf("first install: %v", err)
	}
	cfgPath := filepath.Join(tempHome, ".aws", "config")
	before, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	res, err := InstallAWSProfile("aws.profile.amzn-wanfe", content, opts)
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	for _, f := range res.Files {
		if f.Status != StatusNoChange {
			t.Fatalf("status = %v, want NoChange: %+v", f.Status, res.Files)
		}
	}
	after, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("file rewritten on no-op")
	}
}

func TestInstallAWSProfileUnmanagedSectionTwoPhase(t *testing.T) {
	opts, tempHome := awsTestOptions(t)
	awsDir := filepath.Join(tempHome, ".aws")
	if err := os.MkdirAll(awsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	seedConfig := "[profile personal]\nregion = us-east-1\n"
	seedCreds := "[amzn-wanfe]\naws_access_key_id = HANDEDITED\n"
	if err := os.WriteFile(filepath.Join(awsDir, "config"), []byte(seedConfig), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(awsDir, "credentials"), []byte(seedCreds), 0o600); err != nil {
		t.Fatalf("seed credentials: %v", err)
	}

	content := awsEnvelope(t, "amzn-wanfe", awsTestConfigSection, awsTestCredsSection)
	_, err := InstallAWSProfile("aws.profile.amzn-wanfe", content, opts)
	if !errors.Is(err, ErrUnmanagedSection) {
		t.Fatalf("err = %v, want ErrUnmanagedSection", err)
	}
	if !strings.Contains(err.Error(), "[amzn-wanfe]") || !strings.Contains(err.Error(), "credentials") {
		t.Fatalf("error detail: %v", err)
	}

	cfg, err := os.ReadFile(filepath.Join(awsDir, "config"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(cfg) != seedConfig {
		t.Fatalf("config modified despite credentials failure: %q", cfg)
	}
	creds, err := os.ReadFile(filepath.Join(awsDir, "credentials"))
	if err != nil {
		t.Fatalf("read credentials: %v", err)
	}
	if string(creds) != seedCreds {
		t.Fatalf("credentials modified: %q", creds)
	}
}

func TestInstallAWSProfileForceOverwrites(t *testing.T) {
	opts, tempHome := awsTestOptions(t)
	awsDir := filepath.Join(tempHome, ".aws")
	if err := os.MkdirAll(awsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(awsDir, "credentials"), []byte("[amzn-wanfe]\naws_access_key_id = HANDEDITED\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	opts.Force = true
	content := awsEnvelope(t, "amzn-wanfe", "", awsTestCredsSection)
	res, err := InstallAWSProfile("aws.profile.amzn-wanfe", content, opts)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if len(res.Files) != 1 || res.Files[0].Status != StatusReplaced {
		t.Fatalf("files = %+v", res.Files)
	}
	creds, err := os.ReadFile(filepath.Join(awsDir, "credentials"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(creds) != awsTestCredsSection {
		t.Fatalf("credentials = %q", creds)
	}
}

func TestInstallAWSProfileBackup(t *testing.T) {
	opts, tempHome := awsTestOptions(t)
	awsDir := filepath.Join(tempHome, ".aws")
	if err := os.MkdirAll(awsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	original := "[amzn-wanfe]\naws_access_key_id = HANDEDITED\n"
	if err := os.WriteFile(filepath.Join(awsDir, "credentials"), []byte(original), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	opts.Backup = true
	content := awsEnvelope(t, "amzn-wanfe", "", awsTestCredsSection)
	res, err := InstallAWSProfile("aws.profile.amzn-wanfe", content, opts)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Files[0].Status != StatusBackedUpAndReplaced || res.Files[0].BackupPath == "" {
		t.Fatalf("files = %+v", res.Files)
	}
	backup, err := os.ReadFile(res.Files[0].BackupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backup) != original {
		t.Fatalf("backup content = %q", backup)
	}
	creds, err := os.ReadFile(filepath.Join(awsDir, "credentials"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(creds) != awsTestCredsSection {
		t.Fatalf("credentials = %q", creds)
	}
}

func TestInstallAWSProfileManagedUpdate(t *testing.T) {
	opts, tempHome := awsTestOptions(t)
	v1 := awsEnvelope(t, "amzn-wanfe", "", awsTestCredsSection)
	if _, err := InstallAWSProfile("aws.profile.amzn-wanfe", v1, opts); err != nil {
		t.Fatalf("install v1: %v", err)
	}

	rotated := "[amzn-wanfe]\naws_access_key_id = AKIAROTATED\naws_secret_access_key = newsecret\n"
	v2 := awsEnvelope(t, "amzn-wanfe", "", rotated)
	res, err := InstallAWSProfile("aws.profile.amzn-wanfe", v2, opts)
	if err != nil {
		t.Fatalf("install v2: %v", err)
	}
	if res.Files[0].Status != StatusReplaced {
		t.Fatalf("status = %v, want Replaced", res.Files[0].Status)
	}
	creds, err := os.ReadFile(filepath.Join(tempHome, ".aws", "credentials"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(creds) != rotated {
		t.Fatalf("credentials = %q", creds)
	}

	edited := strings.Replace(rotated, "AKIAROTATED", "TAMPERED", 1)
	if err := os.WriteFile(filepath.Join(tempHome, ".aws", "credentials"), []byte(edited), 0o600); err != nil {
		t.Fatalf("hand edit: %v", err)
	}
	v3 := awsEnvelope(t, "amzn-wanfe", "", awsTestCredsSection)
	if _, err := InstallAWSProfile("aws.profile.amzn-wanfe", v3, opts); !errors.Is(err, ErrUnmanagedSection) {
		t.Fatalf("err = %v, want ErrUnmanagedSection after hand edit", err)
	}
}

func TestInstallAWSProfileSymlinkRefused(t *testing.T) {
	opts, tempHome := awsTestOptions(t)
	awsDir := filepath.Join(tempHome, ".aws")
	if err := os.MkdirAll(awsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(tempHome, "evil")
	if err := os.Symlink(target, filepath.Join(awsDir, "credentials")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	content := awsEnvelope(t, "amzn-wanfe", "", awsTestCredsSection)
	_, err := InstallAWSProfile("aws.profile.amzn-wanfe", content, opts)
	if !errors.Is(err, ErrSymlinkInPath) {
		t.Fatalf("err = %v, want symlink refusal", err)
	}
}

func TestInstallAWSProfileEnvOverride(t *testing.T) {
	opts, tempHome := awsTestOptions(t)
	altConfig := filepath.Join(tempHome, "alt", "aws.conf")
	t.Setenv("AWS_CONFIG_FILE", altConfig)
	content := awsEnvelope(t, "amzn-wanfe", awsTestConfigSection, "")
	res, err := InstallAWSProfile("aws.profile.amzn-wanfe", content, opts)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Files[0].Destination != altConfig {
		t.Fatalf("destination = %q", res.Files[0].Destination)
	}
	if _, err := os.Stat(altConfig); err != nil {
		t.Fatalf("alt config missing: %v", err)
	}
}

func TestInstallAWSProfileRejectsBadEnvelope(t *testing.T) {
	opts, _ := awsTestOptions(t)
	if _, err := InstallAWSProfile("aws.profile.x", []byte("{not json"), opts); err == nil {
		t.Fatalf("expected envelope error")
	}
}

func TestLoadStateLegacyEntryWithoutSections(t *testing.T) {
	tempHome := realTempDir(t)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")
	if err := os.MkdirAll(filepath.Join(kauketHome, "state"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	legacy := `{"schema":1,"installed":{"ssh.main_private_key":{"destination":"~/.ssh/k","expanded_destination":"/home/u/.ssh/k","sha256":"abc","installed_at":"2026-01-01T00:00:00Z"}}}`
	if err := os.WriteFile(filepath.Join(kauketHome, "state", "installed.json"), []byte(legacy), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	state, err := LoadState(kauketHome)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	entry := state.Installed["ssh.main_private_key"]
	if entry.SHA256 != "abc" || entry.Sections != nil {
		t.Fatalf("entry = %+v", entry)
	}
}
