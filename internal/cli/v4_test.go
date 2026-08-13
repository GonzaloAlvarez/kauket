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

func v2StoreWithSecret(t *testing.T) (*testAppBundle, string, string) {
	t.Helper()
	fx, _ := initV2Fixture(t)
	src := filepath.Join(t.TempDir(), "token")
	content := "CLOUD TOKEN VALUE"
	if err := os.WriteFile(src, []byte(content), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := runAdd(context.Background(), fx.app, &addFlags{dest: "/etc/cloud/token"}, "cloud.vendor.api_token", src); err != nil {
		t.Fatalf("add: %v", err)
	}
	adminHome := config.RoleHome(fx.home, config.RoleAdmin)
	cfg, err := config.LoadAdmin(adminHome)
	if err != nil {
		t.Fatalf("load admin: %v", err)
	}
	return fx, cfg.Repo.RemoteHTTPS, content
}

func TestV2EnrollRequestApproveGet(t *testing.T) {
	fx, remoteURL, content := v2StoreWithSecret(t)

	clientBase := t.TempDir()
	clientFake := &ui.Fake{}
	clientApp := &app.App{UI: clientFake, Home: clientBase}
	if err := runEnroll(context.Background(), clientApp, &enrollFlags{
		requests: []string{"cloud/vendor"}, name: "v2machine", remote: remoteURL, yes: true,
	}); err != nil {
		t.Fatalf("v2 enroll: %v", err)
	}
	joined := strings.Join(clientFake.Lines, "\n")
	if !strings.Contains(joined, "created enrollment request rq_") || !strings.Contains(joined, "requested paths: cloud/vendor") {
		t.Fatalf("enroll output: %v", clientFake.Lines)
	}

	err := runGet(context.Background(), clientApp, &getFlags{stdout: true}, "cloud.vendor.api_token")
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitNotGranted {
		t.Fatalf("pre-approve get err = %v, want ExitNotGranted", err)
	}

	fx.fake.Lines = nil
	if err := runApprove(context.Background(), fx.app, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !strings.Contains(strings.Join(fx.fake.Lines, "\n"), "request 1 approved") {
		t.Fatalf("approve output: %v", fx.fake.Lines)
	}

	out := captureStdout(t, func() {
		if err := runGet(context.Background(), clientApp, &getFlags{stdout: true}, "cloud.vendor.api_token"); err != nil {
			t.Fatalf("post-approve get: %v", err)
		}
	})
	if string(out) != content {
		t.Fatalf("content = %q, want %q", out, content)
	}

	if err := runVerify(context.Background(), clientApp, true, false); err != nil {
		t.Fatalf("client verify: %v", err)
	}
}

func TestV2RequestAfterEnrollment(t *testing.T) {
	fx, remoteURL, _ := v2StoreWithSecret(t)

	src := filepath.Join(t.TempDir(), "second")
	if err := os.WriteFile(src, []byte("SECOND SECRET"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := runAdd(context.Background(), fx.app, &addFlags{dest: "/etc/second"}, "other.area.second_secret", src); err != nil {
		t.Fatalf("add second: %v", err)
	}

	clientBase := t.TempDir()
	clientFake := &ui.Fake{}
	clientApp := &app.App{UI: clientFake, Home: clientBase}
	if err := runEnroll(context.Background(), clientApp, &enrollFlags{
		requests: []string{"cloud/vendor"}, name: "requester", remote: remoteURL, yes: true,
	}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := runApprove(context.Background(), fx.app, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("first approve: %v", err)
	}

	clientFake.Lines = nil
	if err := runRequest(context.Background(), clientApp, "other/area", "", true); err != nil {
		t.Fatalf("request: %v", err)
	}
	if !strings.Contains(strings.Join(clientFake.Lines, "\n"), "created access request rq_") {
		t.Fatalf("request output: %v", clientFake.Lines)
	}

	err := runGet(context.Background(), clientApp, &getFlags{stdout: true}, "other.area.second_secret")
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitNotGranted {
		t.Fatalf("pre-approve get err = %v", err)
	}

	if err := runApprove(context.Background(), fx.app, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("second approve: %v", err)
	}

	out := captureStdout(t, func() {
		if err := runGet(context.Background(), clientApp, &getFlags{stdout: true}, "other.area.second_secret"); err != nil {
			t.Fatalf("get after request approval: %v", err)
		}
	})
	if string(out) != "SECOND SECRET" {
		t.Fatalf("content = %q", out)
	}
}

func TestV2JoinUser(t *testing.T) {
	fx, remoteURL, content := v2StoreWithSecret(t)

	userBase := t.TempDir()
	userFake := &ui.Fake{}
	userApp := &app.App{UI: userFake, Home: userBase}
	if err := runJoin(context.Background(), userApp, &joinFlags{
		requests: []string{"cloud/vendor"}, name: "second-human", remote: remoteURL, yes: true,
	}); err != nil {
		t.Fatalf("join: %v", err)
	}
	if !strings.Contains(strings.Join(userFake.Lines, "\n"), "created join request rq_") {
		t.Fatalf("join output: %v", userFake.Lines)
	}

	fx.fake.Lines = nil
	if err := runApprove(context.Background(), fx.app, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve join: %v", err)
	}
	joined := strings.Join(fx.fake.Lines, "\n")
	if !strings.Contains(joined, "(user)") || !strings.Contains(joined, "request 1 approved") {
		t.Fatalf("approve output: %v", fx.fake.Lines)
	}

	out := captureStdout(t, func() {
		if err := runGet(context.Background(), userApp, &getFlags{stdout: true}, "cloud.vendor.api_token"); err != nil {
			t.Fatalf("user get: %v", err)
		}
	})
	if string(out) != content {
		t.Fatalf("user content = %q", out)
	}

	userHome := config.RoleHome(userBase, config.RoleAdmin)
	userCfg, err := config.LoadAdmin(userHome)
	if err != nil {
		t.Fatalf("load user config: %v", err)
	}
	err = runGrant(context.Background(), userApp, userCfg.V2.IdentityID, "cloud/vendor", "", false, true)
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("user grant err = %v, want ExitError", err)
	}
	if !strings.Contains(err.Error(), "not an owner") {
		t.Fatalf("user grant should be refused as non-owner: %v", err)
	}
}

func TestV2ApproveRefusesRecipientRebind(t *testing.T) {
	fx, remoteURL, _ := v2StoreWithSecret(t)

	clientBase := t.TempDir()
	clientApp := &app.App{UI: &ui.Fake{}, Home: clientBase}
	if err := runEnroll(context.Background(), clientApp, &enrollFlags{
		requests: []string{"cloud/vendor"}, name: "victim", remote: remoteURL, yes: true,
	}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := runApprove(context.Background(), fx.app, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	clientHome := config.RoleHome(clientBase, config.RoleClient)
	cfg, err := config.LoadClient(clientHome)
	if err != nil {
		t.Fatalf("load client: %v", err)
	}

	attackerBase := t.TempDir()
	attackerApp := &app.App{UI: &ui.Fake{}, Home: attackerBase}
	if err := runEnroll(context.Background(), attackerApp, &enrollFlags{
		requests: []string{"cloud/vendor"}, name: "attacker", remote: remoteURL, yes: true,
	}); err != nil {
		t.Fatalf("attacker enroll: %v", err)
	}
	attackerHome := config.RoleHome(attackerBase, config.RoleClient)
	attackerCfg, err := config.LoadClient(attackerHome)
	if err != nil {
		t.Fatalf("load attacker: %v", err)
	}
	attackerCfg.Host.ID = cfg.Host.ID
	if err := config.SaveClient(attackerHome, attackerCfg); err != nil {
		t.Fatalf("save attacker: %v", err)
	}
	fake := &ui.Fake{}
	attackerApp.UI = fake
	if err := runRequest(context.Background(), attackerApp, "cloud/vendor", "", true); err != nil {
		t.Fatalf("attacker request: %v", err)
	}

	fx.fake.Lines = nil
	fx.fake.Errors = nil
	if err := runApprove(context.Background(), fx.app, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	foundRefusal := false
	for _, e := range fx.fake.Errors {
		if strings.Contains(e, "already bound to a different recipient") {
			foundRefusal = true
			break
		}
	}
	if !foundRefusal {
		t.Fatalf("expected rebind refusal, errors: %v lines: %v", fx.fake.Errors, fx.fake.Lines)
	}
}
