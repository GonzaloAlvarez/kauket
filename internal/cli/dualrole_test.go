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

func setupDualRoleHome(t *testing.T) (*app.App, *ui.Fake, string, []byte) {
	t.Helper()
	base, _, bareURL := setupAdminStore(t)
	fake := &ui.Fake{}
	a := &app.App{UI: fake, Home: base}

	keyPath := writeSSHKeyFixture(t)
	keyContent, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := runAdd(context.Background(), a, &addFlags{}, "ssh.main_private_key", keyPath); err != nil {
		t.Fatalf("add in admin home: %v", err)
	}

	clientTmp := t.TempDir()
	clientApp := &app.App{UI: &ui.Fake{}, Home: clientTmp}
	if err := runRequest(context.Background(), clientApp, []string{"ssh"}, &requestFlags{name: "dualhost", remote: bareURL, yes: true}); err != nil {
		t.Fatalf("enroll client: %v", err)
	}
	if err := runApprove(context.Background(), a, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve in admin home: %v", err)
	}
	if err := os.Rename(config.RoleHome(clientTmp, config.RoleClient), config.RoleHome(base, config.RoleClient)); err != nil {
		t.Fatalf("move client role into admin base: %v", err)
	}
	fake.Lines = nil
	return a, fake, base, keyContent
}

func TestDualRoleStatusShowsBothSections(t *testing.T) {
	a, fake, _, _ := setupDualRoleHome(t)
	if err := runStatus(context.Background(), a, ""); err != nil {
		t.Fatalf("status: %v", err)
	}
	lines := statusLinesWithoutFingerprint(fake.Lines)
	if len(lines) != 11 {
		t.Fatalf("expected 11 lines (5 admin + blank + 5 client), got %d: %v", len(lines), fake.Lines)
	}
	if lines[0] != "role: admin" {
		t.Fatalf("line 0: %q", lines[0])
	}
	if lines[2] != "schema: 3 (sealed)" {
		t.Fatalf("line 2: %q", lines[2])
	}
	if lines[5] != "" {
		t.Fatalf("line 5 should be blank separator, got %q", lines[5])
	}
	if lines[6] != "role: client" {
		t.Fatalf("line 6: %q", lines[6])
	}
}

func TestDualRoleFullWorkflow(t *testing.T) {
	a, fake, _, keyContent := setupDualRoleHome(t)

	var runErr error
	out := captureStdout(t, func() {
		runErr = runGet(context.Background(), a, &getFlags{stdout: true}, "ssh.main_private_key")
	})
	if runErr != nil {
		t.Fatalf("get: %v", runErr)
	}
	if string(out) != string(keyContent) {
		t.Fatalf("get output mismatch: got %q want %q", string(out), string(keyContent))
	}
	fake.Lines = nil

	if err := runList(context.Background(), a, ""); err != nil {
		t.Fatalf("list: %v", err)
	}
	wantLines := []string{
		"role: admin",
		"ssh.main_private_key",
		"",
		"role: client",
		"ssh.main_private_key",
	}
	if len(fake.Lines) != len(wantLines) {
		t.Fatalf("list lines: got %v want %v", fake.Lines, wantLines)
	}
	for i, w := range wantLines {
		if fake.Lines[i] != w {
			t.Fatalf("list line %d: got %q want %q", i, fake.Lines[i], w)
		}
	}

	fake.Lines = nil
	if err := runList(context.Background(), a, "client"); err != nil {
		t.Fatalf("list --role client: %v", err)
	}
	if len(fake.Lines) != 1 || fake.Lines[0] != "ssh.main_private_key" {
		t.Fatalf("list --role client should be unprefixed, got %v", fake.Lines)
	}
}

func TestDualRoleReverseOrderEnrollThenInit(t *testing.T) {
	_, _, storeURL := setupAdminStore(t)

	a, _, base := newTestApp(t)
	if err := runRequest(context.Background(), a, []string{"ssh"}, &requestFlags{name: "machine2", remote: storeURL, yes: true}); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	initFlagsV := &initFlags{
		owner:       "GonzaloAlvarez",
		repo:        "kauket-store",
		remote:      bareRepo(t),
		yes:         true,
		recoveryOut: filepath.Join(t.TempDir(), "recovery"),
	}
	if err := runInit(context.Background(), a, initFlagsV); err != nil {
		t.Fatalf("init after enroll: %v", err)
	}

	if _, err := config.LoadClient(config.RoleHome(base, config.RoleClient)); err != nil {
		t.Fatalf("load client: %v", err)
	}
	if _, err := config.LoadAdmin(config.RoleHome(base, config.RoleAdmin)); err != nil {
		t.Fatalf("load admin: %v", err)
	}
}

func TestRoleFlagInvalidValue(t *testing.T) {
	a, _, _, _ := setupDualRoleHome(t)
	err := runList(context.Background(), a, "bogus")
	if err == nil {
		t.Fatalf("expected error for invalid --role")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %v", err)
	}
	if !strings.Contains(err.Error(), "invalid --role") {
		t.Fatalf("expected invalid --role message, got %q", err.Error())
	}
}

func TestRoleFlagUninstalledRole(t *testing.T) {
	a, _, _ := initAdminFixture(t)
	err := runList(context.Background(), a, "client")
	if err == nil {
		t.Fatalf("expected error for uninstalled role")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %v", err)
	}
	if !strings.Contains(err.Error(), "client role is not configured") || !strings.Contains(err.Error(), "kauket request") {
		t.Fatalf("expected uninstalled-role hint, got %q", err.Error())
	}
}

func TestAddOnClientOnlyHomeHintsInit(t *testing.T) {
	fx := setupClientOnlyHome(t)
	keyPath := writeSSHKeyFixture(t)
	err := runAdd(context.Background(), fx.app, &addFlags{}, "ssh.main_private_key", keyPath)
	if err == nil {
		t.Fatalf("expected error adding on client-only home")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "requires the admin role") || !strings.Contains(msg, "only has the client role") || !strings.Contains(msg, "kauket init") {
		t.Fatalf("unexpected message: %q", msg)
	}
}
