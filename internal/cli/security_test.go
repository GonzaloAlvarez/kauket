package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/ui"
)

func TestApproveRejectsTraversalHostID(t *testing.T) {
	fx, remoteURL, _ := v2StoreWithSecret(t)

	attackerBase := t.TempDir()
	attackerApp := &app.App{UI: &ui.Fake{}, Home: attackerBase}
	if err := runEnroll(context.Background(), attackerApp, &enrollFlags{
		requests: []string{"cloud/vendor"}, name: "attacker", remote: remoteURL, yes: true,
	}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	attackerHome := config.RoleHome(attackerBase, config.RoleClient)
	attackerCfg, err := config.LoadClient(attackerHome)
	if err != nil {
		t.Fatalf("load attacker: %v", err)
	}
	attackerCfg.Host.ID = "../../../tmp/evil"
	if err := config.SaveClient(attackerHome, attackerCfg); err != nil {
		t.Fatalf("save attacker: %v", err)
	}
	attackerApp.UI = &ui.Fake{}
	if err := runRequest(context.Background(), attackerApp, "cloud/vendor", "", true); err != nil {
		t.Fatalf("request: %v", err)
	}

	fx.fake.Lines = nil
	fx.fake.Errors = nil
	if err := runApprove(context.Background(), fx.app, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	found := false
	for _, e := range fx.fake.Errors {
		if strings.Contains(e, "invalid host id") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected invalid-host-id skip, errors: %v lines: %v", fx.fake.Errors, fx.fake.Lines)
	}
}

func TestResealAlreadySealed(t *testing.T) {
	fx, _, _ := v2StoreWithSecret(t)
	fx.fake.Lines = nil
	if err := runReseal(context.Background(), fx.app); err != nil {
		t.Fatalf("reseal: %v", err)
	}
	if !strings.Contains(strings.Join(fx.fake.Lines, "\n"), "already sealed") {
		t.Fatalf("expected already-sealed message, got: %v", fx.fake.Lines)
	}
}

func TestGrantSubtreeTrailingSlashE2E(t *testing.T) {
	adminApp, _, _, clientApp, _, clientBase, _ := v2StoreFixture(t)
	hostID := clientHostID(t, clientBase)

	err := runGet(context.Background(), clientApp, &getFlags{stdout: true, noSync: true}, "aws.profile.amzn-wanfe")
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitNotGranted {
		t.Fatalf("pre-grant get err = %v, want ExitNotGranted", err)
	}

	if err := runGrant(context.Background(), adminApp, hostID, "aws/", "", false, true); err != nil {
		t.Fatalf("subtree grant: %v", err)
	}
	out := captureStdout(t, func() {
		if err := runGet(context.Background(), clientApp, &getFlags{stdout: true}, "aws.profile.amzn-wanfe"); err != nil {
			t.Fatalf("post subtree-grant get: %v", err)
		}
	})
	if !strings.Contains(string(out), "amzn-wanfe") {
		t.Fatalf("client could not read descendant secret after aws/ grant: %q", out)
	}
}

func TestEnrollWrongAnchorRefused(t *testing.T) {
	_, remoteURL, _ := v2StoreWithSecret(t)

	clientBase := t.TempDir()
	clientApp := &app.App{UI: &ui.Fake{}, Home: clientBase}
	err := runEnroll(context.Background(), clientApp, &enrollFlags{
		requests: []string{"cloud/vendor"}, name: "pinned", remote: remoteURL, yes: true,
		anchor: "SHA256:definitelyNotTheRealAnchorFingerprintAAAAAAAAAAAAAAAAAAA",
	})
	if err == nil {
		t.Fatalf("enroll with wrong anchor should fail")
	}
	if !strings.Contains(err.Error(), "no trust anchor matches") {
		t.Fatalf("err = %v, want anchor-mismatch refusal", err)
	}
}
