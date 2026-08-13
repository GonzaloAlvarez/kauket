package cli

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/manifest"
	"github.com/gonzaloalvarez/kauket/internal/ui"
)

func joinedUserFixture(t *testing.T) (*testAppBundle, *app.App, *ui.Fake, string, string, string) {
	t.Helper()
	fx, remoteURL, content := v2StoreWithSecret(t)

	userBase := t.TempDir()
	userFake := &ui.Fake{}
	userApp := &app.App{UI: userFake, Home: userBase}
	if err := runJoin(context.Background(), userApp, &joinFlags{
		requests: []string{"cloud/vendor"}, name: "co-owner", remote: remoteURL, yes: true,
	}); err != nil {
		t.Fatalf("join: %v", err)
	}
	if err := runApprove(context.Background(), fx.app, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve join: %v", err)
	}
	userHome := config.RoleHome(userBase, config.RoleAdmin)
	userCfg, err := config.LoadAdmin(userHome)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	return fx, userApp, userFake, userCfg.V2.IdentityID, remoteURL, content
}

func TestV2TwoOwnerIndependentGrant(t *testing.T) {
	fx, userApp, userFake, userID, remoteURL, content := joinedUserFixture(t)

	fx.fake.Lines = nil
	if err := runGrant(context.Background(), fx.app, userID, "cloud/vendor", "", true, true); err != nil {
		t.Fatalf("grant --owner: %v", err)
	}
	if !strings.Contains(strings.Join(fx.fake.Lines, "\n"), "granted "+userID+" ownership of cloud/vendor") {
		t.Fatalf("grant output: %v", fx.fake.Lines)
	}

	clientBase := t.TempDir()
	clientApp := &app.App{UI: &ui.Fake{}, Home: clientBase}
	if err := runEnroll(context.Background(), clientApp, &enrollFlags{
		requests: []string{"other/nothing"}, name: "newmachine", remote: remoteURL, yes: true,
	}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	fx.fake.Lines = nil
	fx.fake.Errors = nil
	if err := runApprove(context.Background(), fx.app, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve enrollment: %v", err)
	}

	clientHome := config.RoleHome(clientBase, config.RoleClient)
	clientCfg, err := config.LoadClient(clientHome)
	if err != nil {
		t.Fatalf("load client: %v", err)
	}

	userFake.Lines = nil
	if err := runGrant(context.Background(), userApp, clientCfg.Host.ID, "cloud/vendor", "", false, true); err != nil {
		t.Fatalf("second owner grant: %v", err)
	}
	if !strings.Contains(strings.Join(userFake.Lines, "\n"), "granted "+clientCfg.Host.ID) {
		t.Fatalf("user grant output: %v", userFake.Lines)
	}

	out := captureStdout(t, func() {
		if err := runGet(context.Background(), clientApp, &getFlags{stdout: true}, "cloud.vendor.api_token"); err != nil {
			t.Fatalf("client get after user-signed grant: %v", err)
		}
	})
	if string(out) != content {
		t.Fatalf("content = %q", out)
	}

	if err := runVerify(context.Background(), clientApp, true, false); err != nil {
		t.Fatalf("client verify accepts user-signed manifest: %v", err)
	}
}

func TestV2RevokeOwner(t *testing.T) {
	fx, userApp, _, userID, _, _ := joinedUserFixture(t)
	if err := runGrant(context.Background(), fx.app, userID, "cloud/vendor", "", true, true); err != nil {
		t.Fatalf("grant --owner: %v", err)
	}

	fx.fake.Lines = nil
	if err := runRevoke(context.Background(), fx.app, userID, "cloud/vendor", "", true); err != nil {
		t.Fatalf("revoke --owner: %v", err)
	}
	if !strings.Contains(strings.Join(fx.fake.Lines, "\n"), "revoked "+userID) {
		t.Fatalf("revoke output: %v", fx.fake.Lines)
	}

	userHome := config.RoleHome(userApp.Home, config.RoleAdmin)
	userCfg, err := config.LoadAdmin(userHome)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	err = runGrant(context.Background(), userApp, userCfg.V2.IdentityID, "cloud/vendor", "", false, true)
	if err == nil || (!strings.Contains(err.Error(), "not an owner") && !strings.Contains(err.Error(), "not granted access")) {
		t.Fatalf("revoked owner grant err = %v, want access refusal", err)
	}

	if err := runVerify(context.Background(), fx.app, true, false); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestV2RootOwnerBecomesAnchor(t *testing.T) {
	fx, userApp, _, userID, _, content := joinedUserFixture(t)

	if err := runGrant(context.Background(), fx.app, userID, "/", "", true, true); err != nil {
		t.Fatalf("grant --owner root: %v", err)
	}

	adminHome := config.RoleHome(fx.home, config.RoleAdmin)
	doc, err := os.ReadFile(storeRootPath(config.RepoDir(adminHome)))
	if err != nil {
		t.Fatalf("read store.json: %v", err)
	}
	var root manifest.StoreRoot
	if err := json.Unmarshal(doc, &root); err != nil {
		t.Fatalf("parse store.json: %v", err)
	}
	foundAnchor := false
	for _, a := range root.TrustAnchors {
		if a.IID == userID {
			foundAnchor = true
		}
	}
	if !foundAnchor {
		t.Fatalf("user not in trust anchors: %+v", root.TrustAnchors)
	}

	out := captureStdout(t, func() {
		if err := runGet(context.Background(), userApp, &getFlags{stdout: true}, "cloud.vendor.api_token"); err != nil {
			t.Fatalf("user get with rotated anchors: %v", err)
		}
	})
	if string(out) != content {
		t.Fatalf("content = %q", out)
	}

	fx.fake.Lines = nil
	if err := runRevoke(context.Background(), fx.app, userID, "/", "", true); err != nil {
		t.Fatalf("revoke --owner root: %v", err)
	}
	doc, err = os.ReadFile(storeRootPath(config.RepoDir(adminHome)))
	if err != nil {
		t.Fatalf("read store.json: %v", err)
	}
	if strings.Contains(string(doc), userID) {
		t.Fatalf("user still in store.json after root owner revoke")
	}

	if err := runVerify(context.Background(), fx.app, true, false); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestV2RefusesRemovingLastOwner(t *testing.T) {
	fx, _, _ := v2StoreWithSecret(t)
	adminHome := config.RoleHome(fx.home, config.RoleAdmin)
	cfg, err := config.LoadAdmin(adminHome)
	if err != nil {
		t.Fatalf("load admin: %v", err)
	}
	err = runRevoke(context.Background(), fx.app, cfg.V2.IdentityID, "/", "", true)
	if err == nil || !strings.Contains(err.Error(), "last owner") {
		t.Fatalf("err = %v, want last-owner refusal", err)
	}
}

func TestV2MachineOwnerWarns(t *testing.T) {
	fx, remoteURL, _ := v2StoreWithSecret(t)
	clientBase := t.TempDir()
	clientApp := &app.App{UI: &ui.Fake{}, Home: clientBase}
	if err := runEnroll(context.Background(), clientApp, &enrollFlags{
		requests: []string{"cloud/vendor"}, name: "machine-owner", remote: remoteURL, yes: true,
	}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := runApprove(context.Background(), fx.app, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	clientHome := config.RoleHome(clientBase, config.RoleClient)
	clientCfg, err := config.LoadClient(clientHome)
	if err != nil {
		t.Fatalf("load client: %v", err)
	}

	fake := fx.app.UI.(*ui.Fake)
	fake.ConfirmReply = false
	fake.Lines = nil
	if err := runGrant(context.Background(), fx.app, clientCfg.Host.ID, "cloud/vendor", "", true, false); err != nil {
		t.Fatalf("declined machine owner grant should be nil, got %v", err)
	}

	fake.ConfirmReply = true
	if err := runGrant(context.Background(), fx.app, clientCfg.Host.ID, "cloud/vendor", "", true, false); err != nil {
		t.Fatalf("confirmed machine owner grant: %v", err)
	}

}
