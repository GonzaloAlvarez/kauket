package cli

import (
	"bytes"
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

func initAdminFixture(t *testing.T) (*app.App, *ui.Fake, string) {
	t.Helper()
	fx, _ := initV2Fixture(t)
	fx.fake.Lines = nil
	return fx.app, fx.fake, config.RoleHome(fx.home, config.RoleAdmin)
}

func writeSSHKeyFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "main_private_key.pem")
	body := "-----BEGIN OPENSSH PRIVATE KEY-----\nKAUKETTESTFAKEKEYDATA1234567890abcdefABCDEFghIJKL=\n-----END OPENSSH PRIVATE KEY-----\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestAddSshSecretInfersSpecAndStaysEncrypted(t *testing.T) {
	a, fake, home := initAdminFixture(t)

	keyPath := writeSSHKeyFixture(t)
	if err := runAdd(context.Background(), a, &addFlags{}, "ssh.main_private_key", keyPath); err != nil {
		t.Fatalf("runAdd: %v", err)
	}

	if len(fake.Lines) != 1 {
		t.Fatalf("expected 1 line, got %d: %v", len(fake.Lines), fake.Lines)
	}
	if !strings.HasPrefix(fake.Lines[0], "added ssh.main_private_key") {
		t.Fatalf("line 0: %q", fake.Lines[0])
	}

	want, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	out := captureStdout(t, func() {
		if err := runGet(context.Background(), a, &getFlags{stdout: true, noSync: true}, "ssh.main_private_key"); err != nil {
			t.Fatalf("admin get: %v", err)
		}
	})
	if string(out) != string(want) {
		t.Fatalf("round-trip content mismatch")
	}

	repoDir := config.RepoDir(home)
	for _, needle := range []string{"ssh.main_private_key", "main_private_key", "KAUKETTESTFAKEKEYDATA"} {
		if hits := scanForLiteral(t, repoDir, needle); len(hits) > 0 {
			t.Fatalf("store checkout leaks %q: %v", needle, hits)
		}
	}
}

func TestAddNewSecretVisibleToGrantedClient(t *testing.T) {
	adminApp, _, adminBase, clientApp, _, _, _ := v2StoreFixture(t)

	keyPath := writeSSHKeyFixture(t)
	want, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := runAdd(context.Background(), adminApp, &addFlags{}, "ssh.extra_private_key", keyPath); err != nil {
		t.Fatalf("add extra key: %v", err)
	}

	out := captureStdout(t, func() {
		if err := runGet(context.Background(), clientApp, &getFlags{stdout: true}, "ssh.extra_private_key"); err != nil {
			t.Fatalf("client get new secret in granted namespace: %v", err)
		}
	})
	if string(out) != string(want) {
		t.Fatalf("client content mismatch")
	}

	adminHome := config.RoleHome(adminBase, config.RoleAdmin)
	if hits := scanForLiteral(t, config.RepoDir(adminHome), "extra_private_key"); len(hits) > 0 {
		t.Fatalf("store checkout leaks secret id: %v", hits)
	}
}

func TestAddRejectsInvalidSecretID(t *testing.T) {
	a, _, _ := initAdminFixture(t)
	keyPath := writeSSHKeyFixture(t)
	err := runAdd(context.Background(), a, &addFlags{}, "SSH.main_private_key", keyPath)
	if err == nil {
		t.Fatalf("expected error for invalid id")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %d", exitErr.Code)
	}
}

func TestAddRejectsExistingWithoutForce(t *testing.T) {
	a, fake, _ := initAdminFixture(t)
	keyPath := writeSSHKeyFixture(t)
	if err := runAdd(context.Background(), a, &addFlags{}, "ssh.main_private_key", keyPath); err != nil {
		t.Fatalf("first add: %v", err)
	}
	fake.Lines = nil
	err := runAdd(context.Background(), a, &addFlags{}, "ssh.main_private_key", keyPath)
	if err == nil {
		t.Fatalf("expected error on duplicate add")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %d", exitErr.Code)
	}
	if !strings.Contains(err.Error(), "force") {
		t.Fatalf("expected --force hint, got %q", err.Error())
	}

	fake.Lines = nil
	if err := runAdd(context.Background(), a, &addFlags{force: true}, "ssh.main_private_key", keyPath); err != nil {
		t.Fatalf("force add: %v", err)
	}
	if len(fake.Lines) != 1 || !strings.HasPrefix(fake.Lines[0], "updated ssh.main_private_key") {
		t.Fatalf("expected updated line, got %v", fake.Lines)
	}
}

func TestAddRequiresDestWhenInferenceFails(t *testing.T) {
	a, fake, _ := initAdminFixture(t)
	keyPath := writeSSHKeyFixture(t)
	err := runAdd(context.Background(), a, &addFlags{}, "foo.bar", keyPath)
	if err == nil {
		t.Fatalf("expected error without --dest")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitUsage {
		t.Fatalf("expected ExitUsage, got %d", exitErr.Code)
	}
	if !strings.Contains(err.Error(), "no destination rule") || !strings.Contains(err.Error(), "--dest") {
		t.Fatalf("expected message about destination rule, got %q", err.Error())
	}

	fake.Lines = nil
	if err := runAdd(context.Background(), a, &addFlags{dest: "/etc/foo/bar"}, "foo.bar", keyPath); err != nil {
		t.Fatalf("add with --dest: %v", err)
	}
}

func TestAddRejectsOversizedSource(t *testing.T) {
	a, _, _ := initAdminFixture(t)
	keyPath := filepath.Join(t.TempDir(), "big.bin")
	data := bytes.Repeat([]byte("a"), 8)
	if err := os.WriteFile(keyPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := runAdd(context.Background(), a, &addFlags{maxSize: 4}, "ssh.main_private_key", keyPath)
	if err == nil {
		t.Fatalf("expected oversize error")
	}
	if !strings.Contains(err.Error(), "max size") {
		t.Fatalf("expected max size mention, got %q", err.Error())
	}
}
