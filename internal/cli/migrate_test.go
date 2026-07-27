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

func TestMigrateLegacyAdmin(t *testing.T) {
	base, adminHome, _ := setupAdminStore(t)
	legacyizeRoleHome(t, base, adminHome)

	fake := &ui.Fake{}
	a := &app.App{UI: fake, Home: base}
	if err := runMigrate(a); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if len(fake.Lines) != 1 || !strings.HasPrefix(fake.Lines[0], "migrated admin role to ") {
		t.Fatalf("output: %v", fake.Lines)
	}

	if _, err := config.LoadAdmin(adminHome); err != nil {
		t.Fatalf("load admin from role home: %v", err)
	}
	for _, p := range []string{
		filepath.Join(adminHome, "identities", "admin.txt"),
		filepath.Join(adminHome, "repo", "repo.json"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s after migrate: %v", p, err)
		}
	}
	if _, err := os.Stat(config.ConfigPath(base)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("root config.json should be gone, stat err: %v", err)
	}
	if _, err := os.Stat(config.LockPath(base)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("root repo.lock should be gone, stat err: %v", err)
	}

	fake.Lines = nil
	keyPath := writeSSHKeyFixture(t)
	if err := runAdd(context.Background(), a, &addFlags{}, "ssh.main_private_key", keyPath); err != nil {
		t.Fatalf("add after migrate: %v", err)
	}
}

func TestMigrateLegacyClient(t *testing.T) {
	_, _, bareURL := setupAdminStore(t)
	a, _, base := newTestApp(t)
	flags := &enrollFlags{requests: []string{"ssh"}, name: "machine2", remote: bareURL, yes: true}
	if err := runEnroll(context.Background(), a, flags); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	clientHome := config.RoleHome(base, config.RoleClient)
	legacyizeRoleHome(t, base, clientHome)

	fake := &ui.Fake{}
	migrateApp := &app.App{UI: fake, Home: base}
	if err := runMigrate(migrateApp); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := config.LoadClient(clientHome); err != nil {
		t.Fatalf("load client from role home: %v", err)
	}
	for _, p := range []string{
		filepath.Join(clientHome, "identities", "host.txt"),
		filepath.Join(clientHome, "git", "deploy_key"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s after migrate: %v", p, err)
		}
	}
}

func TestMigrateNothingToDo(t *testing.T) {
	a, fake, _ := newTestApp(t)
	if err := runMigrate(a); err != nil {
		t.Fatalf("migrate on empty home: %v", err)
	}
	if len(fake.Lines) != 1 || fake.Lines[0] != "nothing to migrate" {
		t.Fatalf("output: %v", fake.Lines)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	base, adminHome, _ := setupAdminStore(t)
	legacyizeRoleHome(t, base, adminHome)

	fake := &ui.Fake{}
	a := &app.App{UI: fake, Home: base}
	if err := runMigrate(a); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	fake.Lines = nil
	if err := runMigrate(a); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if len(fake.Lines) != 1 || fake.Lines[0] != "nothing to migrate" {
		t.Fatalf("second run output: %v", fake.Lines)
	}
}

func TestMigrateRefusesWhenTargetConfigExists(t *testing.T) {
	base, adminHome, _ := setupAdminStore(t)
	legacyizeRoleHome(t, base, adminHome)
	if err := config.SaveAdmin(adminHome, &config.Admin{Schema: config.ConfigSchema, Role: config.RoleAdmin}); err != nil {
		t.Fatalf("plant target config: %v", err)
	}

	a := &app.App{UI: &ui.Fake{}, Home: base}
	err := runMigrate(a)
	if err == nil {
		t.Fatalf("expected refusal when target config exists")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %v", err)
	}
	if !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("unexpected message: %q", err.Error())
	}
	if _, err := config.LoadAdmin(base); err != nil {
		t.Fatalf("legacy root config must be untouched: %v", err)
	}
}

func TestMigrateResumesAfterInterruption(t *testing.T) {
	base, adminHome, _ := setupAdminStore(t)
	legacyizeRoleHome(t, base, adminHome)

	if err := os.MkdirAll(adminHome, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	if err := os.Rename(filepath.Join(base, "identities"), filepath.Join(adminHome, "identities")); err != nil {
		t.Fatalf("pre-move identities: %v", err)
	}

	a := &app.App{UI: &ui.Fake{}, Home: base}
	if err := runMigrate(a); err != nil {
		t.Fatalf("resumed migrate: %v", err)
	}
	if _, err := config.LoadAdmin(adminHome); err != nil {
		t.Fatalf("load admin after resume: %v", err)
	}
	if _, err := os.Stat(filepath.Join(adminHome, "identities", "admin.txt")); err != nil {
		t.Fatalf("identities missing after resume: %v", err)
	}
	if _, err := os.Stat(filepath.Join(adminHome, "repo", "repo.json")); err != nil {
		t.Fatalf("repo missing after resume: %v", err)
	}
}
