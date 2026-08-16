package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/ui"
)

func initV2Fixture(t *testing.T) (*testAppBundle, string) {
	t.Helper()
	a, fake, home := newTestApp(t)
	recoveryOut := filepath.Join(t.TempDir(), "recovery")
	flags := &initFlags{
		owner:       "GonzaloAlvarez",
		repo:        "kauket-store",
		remote:      bareRepo(t),
		yes:         true,
		recoveryOut: recoveryOut,
	}
	if err := runInit(context.Background(), a, flags); err != nil {
		t.Fatalf("runInit: %v", err)
	}
	return &testAppBundle{app: a, fake: fake, home: home}, recoveryOut
}

type testAppBundle struct {
	app  *app.App
	fake *ui.Fake
	home string
}

func TestInitV2CreatesReadableStore(t *testing.T) {
	fx, recoveryOut := initV2Fixture(t)
	adminHome := config.RoleHome(fx.home, config.RoleAdmin)
	repoDir := config.RepoDir(adminHome)

	if !isV2Store(repoDir) {
		t.Fatalf("store.json missing")
	}
	if _, err := os.Stat(storeRootSigPath(repoDir)); err != nil {
		t.Fatalf("store.json.sig missing: %v", err)
	}
	entries, err := os.ReadDir(objectsDir(repoDir))
	if err != nil || len(entries) != 2 {
		t.Fatalf("objects dir: %v entries, err %v", len(entries), err)
	}
	ids, err := os.ReadDir(repoIdentitiesDir(repoDir))
	if err != nil || len(ids) != 1 {
		t.Fatalf("identities dir: %v entries, err %v", len(ids), err)
	}
	for _, f := range []string{"recovery-age.txt", "recovery-sign.key"} {
		if _, err := os.Stat(filepath.Join(recoveryOut, f)); err != nil {
			t.Fatalf("recovery file %s missing: %v", f, err)
		}
	}

	cfg, err := config.LoadAdmin(adminHome)
	if err != nil {
		t.Fatalf("load admin: %v", err)
	}
	if cfg.V2 == nil || cfg.V2.IdentityID == "" || !strings.HasPrefix(cfg.V2.IdentityID, "i_") {
		t.Fatalf("config v2 info = %+v", cfg.V2)
	}

	fx.fake.Lines = nil
	if err := runVerify(context.Background(), fx.app, false); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(fx.fake.Lines) != 1 || fx.fake.Lines[0] != "verified 1 nodes, 0 entries" {
		t.Fatalf("verify output: %v", fx.fake.Lines)
	}

	fx.fake.Lines = nil
	if err := runStatus(context.Background(), fx.app, ""); err != nil {
		t.Fatalf("status: %v", err)
	}
	joined := strings.Join(fx.fake.Lines, "\n")
	if !strings.Contains(joined, "schema: 3") || !strings.Contains(joined, "role: admin") {
		t.Fatalf("status output: %v", fx.fake.Lines)
	}

	fx.fake.Lines = nil
	if err := runList(context.Background(), fx.app, ""); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(fx.fake.Lines) != 0 {
		t.Fatalf("list on empty store: %v", fx.fake.Lines)
	}
}

func TestInitV2RequiresRecoveryOut(t *testing.T) {
	a, _, _ := newTestApp(t)
	flags := &initFlags{owner: "o", repo: "r", remote: bareRepo(t), yes: true}
	err := runInit(context.Background(), a, flags)
	if err == nil || !strings.Contains(err.Error(), "--recovery-out") {
		t.Fatalf("err = %v", err)
	}
}

func v2StoreFixture(t *testing.T) (adminApp *app.App, adminFake *ui.Fake, adminBase string, clientApp *app.App, clientFake *ui.Fake, clientBase string, keyContent []byte) {
	t.Helper()
	fx, _ := initV2Fixture(t)
	aApp, aFake, base := fx.app, fx.fake, fx.home
	adminHome := config.RoleHome(base, config.RoleAdmin)
	cfg, err := config.LoadAdmin(adminHome)
	if err != nil {
		t.Fatalf("load admin: %v", err)
	}
	bareURL := cfg.Repo.RemoteHTTPS

	keyPath := writeSSHKeyFixture(t)
	keyContent, err = os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key fixture: %v", err)
	}
	if err := runAdd(context.Background(), aApp, &addFlags{}, "ssh.main_private_key", keyPath); err != nil {
		t.Fatalf("add ssh: %v", err)
	}
	writeAWSFixture(t, awsCliConfigSection, awsCliCredsSection)
	if err := runAdd(context.Background(), aApp, &addFlags{awsProfile: "amzn-wanfe"}, "", ""); err != nil {
		t.Fatalf("add aws profile: %v", err)
	}

	cBase := t.TempDir()
	cFake := &ui.Fake{}
	cApp := &app.App{UI: cFake, Home: cBase}
	if err := runRequest(context.Background(), cApp, []string{"ssh"}, &requestFlags{name: "machine2", remote: bareURL, yes: true}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := runApprove(context.Background(), aApp, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := syncClient(context.Background(), cApp, config.RoleHome(cBase, config.RoleClient)); err != nil {
		t.Fatalf("client sync: %v", err)
	}
	aFake.Lines = nil
	cFake.Lines = nil
	return aApp, aFake, base, cApp, cFake, cBase, keyContent
}

func TestV2StoreEndToEnd(t *testing.T) {
	adminApp, adminFake, adminBase, clientApp, clientFake, _, keyContent := v2StoreFixture(t)
	adminHome := config.RoleHome(adminBase, config.RoleAdmin)
	repoDir := config.RepoDir(adminHome)

	if !isV2Store(repoDir) {
		t.Fatalf("store not v2")
	}

	out := captureStdout(t, func() {
		if err := runGet(context.Background(), adminApp, &getFlags{stdout: true}, "ssh.main_private_key"); err != nil {
			t.Fatalf("admin get: %v", err)
		}
	})
	if string(out) != string(keyContent) {
		t.Fatalf("admin get content mismatch")
	}

	out = captureStdout(t, func() {
		if err := runGet(context.Background(), clientApp, &getFlags{stdout: true}, "ssh.main_private_key"); err != nil {
			t.Fatalf("client get: %v", err)
		}
	})
	if string(out) != string(keyContent) {
		t.Fatalf("client get content mismatch")
	}

	err := runGet(context.Background(), clientApp, &getFlags{stdout: true}, "aws.profile.amzn-wanfe")
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitNotGranted {
		t.Fatalf("client aws get err = %v, want ExitNotGranted", err)
	}

	clientFake.Lines = nil
	if err := runList(context.Background(), clientApp, ""); err != nil {
		t.Fatalf("client list: %v", err)
	}
	if len(clientFake.Lines) != 1 || clientFake.Lines[0] != "ssh.main_private_key" {
		t.Fatalf("client list: %v", clientFake.Lines)
	}

	adminFake.Lines = nil
	if err := runList(context.Background(), adminApp, ""); err != nil {
		t.Fatalf("admin list: %v", err)
	}
	joined := strings.Join(adminFake.Lines, "\n")
	if !strings.Contains(joined, "ssh.main_private_key") || !strings.Contains(joined, "aws.profile.amzn-wanfe") {
		t.Fatalf("admin list: %v", adminFake.Lines)
	}

	clientFake.Lines = nil
	if err := runVerify(context.Background(), clientApp, false); err != nil {
		t.Fatalf("client verify: %v", err)
	}
}

func TestVerifyDetectsTamperedObject(t *testing.T) {
	adminApp, _, adminBase, _, _, _, _ := v2StoreFixture(t)
	adminHome := config.RoleHome(adminBase, config.RoleAdmin)
	dir := objectsDir(config.RepoDir(adminHome))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read objects: %v", err)
	}
	tampered := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "o_") {
			if err := os.WriteFile(filepath.Join(dir, e.Name()), []byte("garbage"), 0o600); err != nil {
				t.Fatalf("tamper: %v", err)
			}
			tampered = true
			break
		}
	}
	if !tampered {
		t.Fatalf("no secret object found to tamper")
	}
	breakStoreRemote(t, adminHome)
	err = runVerify(context.Background(), adminApp, false)
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitCrypto {
		t.Fatalf("verify err = %v, want ExitCrypto", err)
	}
}
