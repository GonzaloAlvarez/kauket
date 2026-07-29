package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/gonzaloalvarez/kauket/internal/config"
)

func clientHostID(t *testing.T, clientBase string) string {
	t.Helper()
	clientHome := config.RoleHome(clientBase, config.RoleClient)
	cfg, err := config.LoadClient(clientHome)
	if err != nil {
		t.Fatalf("load client: %v", err)
	}
	return cfg.Host.ID
}

func TestGrantRevokeRoundtrip(t *testing.T) {
	adminApp, adminFake, _, clientApp, _, clientBase, _ := migratedStoreFixture(t)
	hostID := clientHostID(t, clientBase)

	err := runGet(context.Background(), clientApp, &getFlags{stdout: true, noSync: true}, "aws.profile.amzn-wanfe")
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitNotGranted {
		t.Fatalf("pre-grant get err = %v, want ExitNotGranted", err)
	}

	adminFake.Lines = nil
	if err := runGrant(context.Background(), adminApp, hostID, "aws/profile", "", false, true); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if !strings.Contains(strings.Join(adminFake.Lines, "\n"), "granted "+hostID) {
		t.Fatalf("grant output: %v", adminFake.Lines)
	}

	out := captureStdout(t, func() {
		if err := runGet(context.Background(), clientApp, &getFlags{stdout: true}, "aws.profile.amzn-wanfe"); err != nil {
			t.Fatalf("post-grant get: %v", err)
		}
	})
	if !strings.Contains(string(out), "amzn-wanfe") {
		t.Fatalf("post-grant content: %q", out)
	}

	adminFake.Lines = nil
	if err := runGrant(context.Background(), adminApp, hostID, "aws/profile", "", false, true); err != nil {
		t.Fatalf("idempotent grant: %v", err)
	}
	if !strings.Contains(strings.Join(adminFake.Lines, "\n"), "already has access") {
		t.Fatalf("idempotent grant output: %v", adminFake.Lines)
	}

	adminFake.Lines = nil
	if err := runRevoke(context.Background(), adminApp, hostID, "aws/profile", "", false); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	joined := strings.Join(adminFake.Lines, "\n")
	if !strings.Contains(joined, "revoked "+hostID) || !strings.Contains(joined, "rotate these secrets") || !strings.Contains(joined, "aws/profile/amzn-wanfe") {
		t.Fatalf("revoke output: %v", adminFake.Lines)
	}

	err = runGet(context.Background(), clientApp, &getFlags{stdout: true}, "aws.profile.amzn-wanfe")
	if !errors.As(err, &exitErr) || exitErr.Code != ExitNotGranted {
		t.Fatalf("post-revoke get err = %v, want ExitNotGranted", err)
	}

	adminFake.Lines = nil
	if err := runVerify(context.Background(), adminApp, true); err != nil {
		t.Fatalf("verify after grant/revoke: %v", err)
	}
}

func TestGrantSingleKey(t *testing.T) {
	adminApp, _, _, clientApp, clientFake, clientBase, keyContent := migratedStoreFixture(t)
	hostID := clientHostID(t, clientBase)

	keyPath := writeSSHKeyFixture(t)
	if err := runAdd(context.Background(), adminApp, &addFlags{}, "ssh.extra_private_key", keyPath); err != nil {
		t.Fatalf("add on v2: %v", err)
	}

	if err := runGrant(context.Background(), adminApp, hostID, "infra/k8s", "--missing--", false, true); err == nil {
		t.Fatalf("grant of missing key should fail")
	}

	if err := runGrant(context.Background(), adminApp, hostID, "aws/profile", "amzn-wanfe", false, true); err != nil {
		t.Fatalf("grant single key: %v", err)
	}
	out := captureStdout(t, func() {
		if err := runGet(context.Background(), clientApp, &getFlags{stdout: true}, "aws.profile.amzn-wanfe"); err != nil {
			t.Fatalf("get granted key: %v", err)
		}
	})
	if !strings.Contains(string(out), "amzn-wanfe") {
		t.Fatalf("content: %q", out)
	}

	clientFake.Lines = nil
	if err := runVerify(context.Background(), clientApp, true); err != nil {
		t.Fatalf("client verify: %v", err)
	}
	_ = keyContent
}

func TestAddV2CreatesIntermediateNodes(t *testing.T) {
	adminApp, adminFake, adminBase, _, _, _, _ := migratedStoreFixture(t)

	src := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(src, []byte("DEEP TOKEN VALUE"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	adminFake.Lines = nil
	if err := runAdd(context.Background(), adminApp, &addFlags{dest: "/etc/deep/token"}, "brandnew.deep.nested.api_token", src); err != nil {
		t.Fatalf("add nested: %v", err)
	}
	if !strings.Contains(strings.Join(adminFake.Lines, "\n"), "added brandnew.deep.nested.api_token") {
		t.Fatalf("add output: %v", adminFake.Lines)
	}

	out := captureStdout(t, func() {
		if err := runGet(context.Background(), adminApp, &getFlags{stdout: true, noSync: true}, "brandnew.deep.nested.api_token"); err != nil {
			t.Fatalf("get nested: %v", err)
		}
	})
	if string(out) != "DEEP TOKEN VALUE" {
		t.Fatalf("content: %q", out)
	}

	err := runAdd(context.Background(), adminApp, &addFlags{dest: "/etc/deep/token"}, "brandnew.deep.nested.api_token", src)
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("duplicate add err = %v, want force hint", err)
	}
	if err := runAdd(context.Background(), adminApp, &addFlags{dest: "/etc/deep/token", force: true}, "brandnew.deep.nested.api_token", src); err != nil {
		t.Fatalf("force add: %v", err)
	}

	adminHome := config.RoleHome(adminBase, config.RoleAdmin)
	_ = adminHome
	if err := runVerify(context.Background(), adminApp, true); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestGrantUnknownIdentityFails(t *testing.T) {
	adminApp, _, _, _, _, _, _ := migratedStoreFixture(t)
	err := runGrant(context.Background(), adminApp, "i_doesnotexist12345", "aws/profile", "", false, true)
	if err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatalf("err = %v, want not-enrolled", err)
	}
}

func TestNonFFRecomputeRetry(t *testing.T) {
	adminApp, _, adminBase, _, _, clientBase, _ := migratedStoreFixture(t)
	hostID := clientHostID(t, clientBase)
	adminHome := config.RoleHome(adminBase, config.RoleAdmin)
	adminCfg, err := config.LoadAdmin(adminHome)
	if err != nil {
		t.Fatalf("load admin: %v", err)
	}
	bareDir := strings.TrimPrefix(adminCfg.Repo.RemoteHTTPS, "file://")

	pushed := false
	origNow := adminApp.Now
	adminApp.Now = func() time.Time {
		if !pushed {
			pushed = true
			commitToBare(t, bareDir)
		}
		if origNow != nil {
			return origNow()
		}
		return time.Now()
	}
	defer func() { adminApp.Now = origNow }()

	if err := runGrant(context.Background(), adminApp, hostID, "aws/profile", "", false, true); err != nil {
		t.Fatalf("grant with concurrent writer: %v", err)
	}
	if err := runVerify(context.Background(), adminApp, false); err != nil {
		t.Fatalf("verify after race: %v", err)
	}
}

func commitToBare(t *testing.T, bareDir string) {
	t.Helper()
	work := t.TempDir()
	repo, err := gogit.PlainClone(work, false, &gogit.CloneOptions{URL: bareDir})
	if err != nil {
		t.Fatalf("clone bare: %v", err)
	}
	if err := os.WriteFile(filepath.Join(work, "concurrent-marker"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if _, err := wt.Add("concurrent-marker"); err != nil {
		t.Fatalf("add: %v", err)
	}
	sig := &object.Signature{Name: "racer", Email: "racer@example.com", When: time.Now()}
	if _, err := wt.Commit("concurrent commit", &gogit.CommitOptions{Author: sig, Committer: sig}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := repo.Push(&gogit.PushOptions{}); err != nil {
		t.Fatalf("push: %v", err)
	}
}
