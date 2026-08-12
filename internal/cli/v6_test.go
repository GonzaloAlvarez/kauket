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

func v2StoreWithRecoveryDir(t *testing.T) (*testAppBundle, string, string) {
	t.Helper()
	a, fake, home := newTestApp(t)
	recoveryOut := filepath.Join(t.TempDir(), "recovery")
	flags := &initFlags{
		owner: "GonzaloAlvarez", repo: "kauket-store", private: true,
		remote: bareRepo(t), noGitHub: true, yes: true, recoveryOut: recoveryOut,
	}
	if err := runInit(context.Background(), a, flags); err != nil {
		t.Fatalf("init: %v", err)
	}
	fx := &testAppBundle{app: a, fake: fake, home: home}
	src := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(src, []byte("RESCUE TOKEN"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := runAdd(context.Background(), a, &addFlags{dest: "/etc/cloud/token"}, "cloud.vendor.api_token", src); err != nil {
		t.Fatalf("add: %v", err)
	}
	adminHome := config.RoleHome(home, config.RoleAdmin)
	cfg, err := config.LoadAdmin(adminHome)
	if err != nil {
		t.Fatalf("load admin: %v", err)
	}
	return fx, cfg.Repo.RemoteHTTPS, recoveryOut
}

func TestV2RescueOrphanedNode(t *testing.T) {
	fx, remoteURL, recoveryOut := v2StoreWithRecoveryDir(t)

	userBase := t.TempDir()
	userApp := &app.App{UI: &ui.Fake{}, Home: userBase}
	if err := runJoin(context.Background(), userApp, &joinFlags{
		requests: []string{"cloud/vendor"}, name: "new-owner", remote: remoteURL, yes: true,
	}); err != nil {
		t.Fatalf("join: %v", err)
	}
	if err := runApprove(context.Background(), fx.app, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	userHome := config.RoleHome(userBase, config.RoleAdmin)
	userCfg, err := config.LoadAdmin(userHome)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}

	fx.fake.Lines = nil
	if err := runRescue(context.Background(), fx.app, &rescueFlags{
		recoveryIdentity: filepath.Join(recoveryOut, "recovery-age.txt"),
		recoverySignKey:  filepath.Join(recoveryOut, "recovery-sign.key"),
		newOwner:         userCfg.V2.IdentityID,
	}, "cloud/vendor"); err != nil {
		t.Fatalf("rescue: %v", err)
	}
	if !strings.Contains(strings.Join(fx.fake.Lines, "\n"), "rescued cloud/vendor") {
		t.Fatalf("rescue output: %v", fx.fake.Lines)
	}

	userFake := userApp.UI.(*ui.Fake)
	userFake.Lines = nil
	if err := runGrant(context.Background(), userApp, userCfg.V2.IdentityID, "cloud/vendor", "", false, true); err != nil {
		t.Fatalf("new owner grant (self, already owner): %v", err)
	}

	out := captureStdout(t, func() {
		if err := runGet(context.Background(), userApp, &getFlags{stdout: true}, "cloud.vendor.api_token"); err != nil {
			t.Fatalf("new owner get: %v", err)
		}
	})
	if string(out) != "RESCUE TOKEN" {
		t.Fatalf("content = %q", out)
	}

	if err := runVerify(context.Background(), fx.app, true); err != nil {
		t.Fatalf("verify after rescue: %v", err)
	}
}

func TestV2RescueRejectsWrongRecoveryKey(t *testing.T) {
	fx, remoteURL, _ := v2StoreWithRecoveryDir(t)
	userBase := t.TempDir()
	userApp := &app.App{UI: &ui.Fake{}, Home: userBase}
	if err := runJoin(context.Background(), userApp, &joinFlags{
		requests: []string{"cloud/vendor"}, name: "u", remote: remoteURL, yes: true,
	}); err != nil {
		t.Fatalf("join: %v", err)
	}
	if err := runApprove(context.Background(), fx.app, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	userHome := config.RoleHome(userBase, config.RoleAdmin)
	userCfg, _ := config.LoadAdmin(userHome)

	fakeRecovery := t.TempDir()
	if _, _, err := writeRecoveryPair(fakeRecovery); err != nil {
		t.Fatalf("fake recovery: %v", err)
	}
	err := runRescue(context.Background(), fx.app, &rescueFlags{
		recoveryIdentity: filepath.Join(fakeRecovery, "recovery-age.txt"),
		recoverySignKey:  filepath.Join(fakeRecovery, "recovery-sign.key"),
		newOwner:         userCfg.V2.IdentityID,
	}, "cloud/vendor")
	if err == nil || !strings.Contains(err.Error(), "not a recovery anchor") {
		t.Fatalf("err = %v, want recovery-anchor refusal", err)
	}
}

func TestV2InspectMatchesReality(t *testing.T) {
	fx, remoteURL, _ := v2StoreWithRecoveryDir(t)

	src := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(src, []byte("OTHER"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := runAdd(context.Background(), fx.app, &addFlags{dest: "/etc/other"}, "other.area.secret", src); err != nil {
		t.Fatalf("add other: %v", err)
	}

	clientBase := t.TempDir()
	clientApp := &app.App{UI: &ui.Fake{}, Home: clientBase}
	if err := runEnroll(context.Background(), clientApp, &enrollFlags{
		requests: []string{"cloud/vendor"}, name: "inspectee", remote: remoteURL, yes: true,
	}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := runApprove(context.Background(), fx.app, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	clientHome := config.RoleHome(clientBase, config.RoleClient)
	clientCfg, _ := config.LoadClient(clientHome)

	fx.fake.Lines = nil
	if err := runInspectAs(context.Background(), fx.app, clientCfg.Host.ID, true); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	joined := strings.Join(fx.fake.Lines, "\n")
	if !strings.Contains(joined, "can read 1 secrets") || !strings.Contains(joined, "cloud.vendor.api_token") {
		t.Fatalf("inspect output: %v", fx.fake.Lines)
	}
	if strings.Contains(joined, "other.area.secret") {
		t.Fatalf("inspect leaked ungranted secret: %v", fx.fake.Lines)
	}

	if err := runGet(context.Background(), clientApp, &getFlags{stdout: true}, "cloud.vendor.api_token"); err != nil {
		t.Fatalf("reality: granted get failed: %v", err)
	}
	err := runGet(context.Background(), clientApp, &getFlags{stdout: true, noSync: true}, "other.area.secret")
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitNotGranted {
		t.Fatalf("reality: ungranted get err = %v, want ExitNotGranted", err)
	}
}
