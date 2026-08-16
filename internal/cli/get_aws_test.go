package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/awsconfig"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/manifest"
	"github.com/gonzaloalvarez/kauket/internal/ui"
)

const (
	awsCliConfigSection = "[profile amzn-wanfe]\nregion = us-west-2\nsso_session = amzn\n\n[sso-session amzn]\nsso_start_url = https://amzn.awsapps.com/start\n"
	awsCliCredsSection  = "[amzn-wanfe]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = secretvalue\n"
)

func setupClientWithAWSProfile(t *testing.T) *clientFixture {
	t.Helper()
	adminFx, _ := initV2Fixture(t)
	adminHome := config.RoleHome(adminFx.home, config.RoleAdmin)
	cfg, err := config.LoadAdmin(adminHome)
	if err != nil {
		t.Fatalf("load admin: %v", err)
	}
	bareURL := cfg.Repo.RemoteHTTPS

	writeAWSFixture(t, awsCliConfigSection, awsCliCredsSection)
	if err := runAdd(context.Background(), adminFx.app, &addFlags{awsProfile: "amzn-wanfe"}, "", ""); err != nil {
		t.Fatalf("add aws profile: %v", err)
	}

	tempHome := t.TempDir()
	resolved, err := filepath.EvalSymlinks(tempHome)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	tempHome = resolved
	t.Setenv("HOME", tempHome)
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")

	kauketBase := filepath.Join(tempHome, ".config", "kauket")
	fake := &ui.Fake{}
	clientApp := &app.App{UI: fake, Home: kauketBase}
	if err := runRequest(context.Background(), clientApp, []string{"aws/profile"}, &requestFlags{name: "machine2", remote: bareURL, yes: true}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := runApprove(context.Background(), adminFx.app, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := syncClient(context.Background(), clientApp, config.RoleHome(kauketBase, config.RoleClient)); err != nil {
		t.Fatalf("client sync: %v", err)
	}
	adminFx.fake.Lines = nil
	fake.Lines = nil

	return &clientFixture{
		app:      clientApp,
		fake:     fake,
		home:     config.RoleHome(kauketBase, config.RoleClient),
		tempHome: tempHome,
		admin:    adminFx,
		bareURL:  bareURL,
	}
}

func TestGetAWSProfileMergesAlongsideExisting(t *testing.T) {
	fx := setupClientWithAWSProfile(t)
	awsDir := filepath.Join(fx.tempHome, ".aws")
	if err := os.MkdirAll(awsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	existing := "[profile personal]\nregion = us-east-1\n"
	if err := os.WriteFile(filepath.Join(awsDir, "config"), []byte(existing), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	flags := &getFlags{}
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
	fx := setupClientWithAWSProfile(t)
	flags := &getFlags{}
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
	fx := setupClientWithAWSProfile(t)
	flags := &getFlags{stdout: true}
	out := captureStdout(t, func() {
		if err := runGet(context.Background(), fx.app, flags, "aws.profile.amzn-wanfe"); err != nil {
			t.Fatalf("runGet: %v", err)
		}
	})
	env, err := awsconfig.ParseEnvelope(out)
	if err != nil {
		t.Fatalf("stdout is not an aws envelope: %v", err)
	}
	if env.Profile != "amzn-wanfe" {
		t.Fatalf("envelope profile = %q", env.Profile)
	}
	if !strings.Contains(env.Config, "[profile amzn-wanfe]") || !strings.Contains(env.Config, "[sso-session amzn]") {
		t.Fatalf("envelope config = %q", env.Config)
	}
	if env.Credentials != awsCliCredsSection {
		t.Fatalf("envelope credentials = %q", env.Credentials)
	}
	if _, err := os.Stat(filepath.Join(fx.tempHome, ".aws")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stdout mode should not touch ~/.aws; stat err = %v", err)
	}
}

func addRawKindObject(t *testing.T, fx *testAppBundle, secretID, kind string, content []byte) {
	t.Helper()
	adminHome := config.RoleHome(fx.home, config.RoleAdmin)
	cfg, err := config.LoadAdmin(adminHome)
	if err != nil {
		t.Fatalf("load admin: %v", err)
	}
	vctx, err := loadV2Context(adminHome, cfg.Admin.IdentityPath, cfg.V2)
	if err != nil {
		t.Fatalf("load v2 context: %v", err)
	}
	signKeyPath := cfg.V2.SignKeyPath
	if !filepath.IsAbs(signKeyPath) {
		signKeyPath = filepath.Join(adminHome, signKeyPath)
	}
	signerPub, err := ensureSignKey(signKeyPath)
	if err != nil {
		t.Fatalf("sign key: %v", err)
	}
	path, key, err := splitSecretPath(secretID)
	if err != nil {
		t.Fatalf("split path: %v", err)
	}
	sum := sha256.Sum256(content)
	engine := &manifest.Engine{
		ObjectsDir: objectsDir(vctx.repoDir),
		Root:       vctx.root,
		Pins:       vctx.pins,
		Identity:   vctx.identity,
		Signer:     bundle.Ed25519FileSigner{Path: signKeyPath},
		SignerPub:  signerPub,
		ActorID:    cfg.V2.IdentityID,
	}
	if _, err := engine.Apply(manifest.Intent{
		Op: manifest.OpAdd, Path: path, Key: key,
		Secret: &manifest.Object{
			Kind:          kind,
			ContentBase64: base64.StdEncoding.EncodeToString(content),
			SHA256:        hex.EncodeToString(sum[:]),
		},
	}); err != nil {
		t.Fatalf("engine apply: %v", err)
	}
	if err := vctx.savePins(); err != nil {
		t.Fatalf("save pins: %v", err)
	}
}

func TestGetUnsupportedKind(t *testing.T) {
	fx, _ := initV2Fixture(t)
	addRawKindObject(t, fx, "weird.thing", "pkcs11", []byte("OPAQUE"))
	breakStoreRemote(t, config.RoleHome(fx.home, config.RoleAdmin))

	err := runGet(context.Background(), fx.app, &getFlags{}, "weird.thing")
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
	fx := setupClientWithAWSProfile(t)
	awsDir := filepath.Join(fx.tempHome, ".aws")
	if err := os.MkdirAll(awsDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(awsDir, "credentials"), []byte("[amzn-wanfe]\naws_access_key_id = HANDEDITED\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	flags := &getFlags{}
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
	if err := runGet(context.Background(), fx.app, &getFlags{force: true}, "aws.profile.amzn-wanfe"); err != nil {
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
