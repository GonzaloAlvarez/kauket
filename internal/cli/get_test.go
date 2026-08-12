package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/ui"
)

const testSecretID = "ssh.main_private_key"

type clientFixture struct {
	app      *app.App
	fake     *ui.Fake
	home     string
	tempHome string
	admin    *testAppBundle
	dest     string
	content  []byte
	bareURL  string
}

func setupEnrolledClient(t *testing.T, requestPath string) *clientFixture {
	t.Helper()
	adminFx, _ := initV2Fixture(t)
	adminHome := config.RoleHome(adminFx.home, config.RoleAdmin)
	cfg, err := config.LoadAdmin(adminHome)
	if err != nil {
		t.Fatalf("load admin: %v", err)
	}
	bareURL := cfg.Repo.RemoteHTTPS

	keyPath := writeSSHKeyFixture(t)
	content, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key fixture: %v", err)
	}
	if err := runAdd(context.Background(), adminFx.app, &addFlags{}, testSecretID, keyPath); err != nil {
		t.Fatalf("add ssh: %v", err)
	}

	tempHome := t.TempDir()
	resolved, err := filepath.EvalSymlinks(tempHome)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	tempHome = resolved
	t.Setenv("HOME", tempHome)

	kauketBase := filepath.Join(tempHome, ".config", "kauket")
	fake := &ui.Fake{}
	clientApp := &app.App{UI: fake, Home: kauketBase}
	if err := runEnroll(context.Background(), clientApp, &enrollFlags{
		requests: []string{requestPath}, name: "machine2", remote: bareURL, yes: true,
	}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if err := runApprove(context.Background(), adminFx.app, &approveFlags{all: true, yes: true}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := runSync(context.Background(), clientApp, ""); err != nil {
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
		dest:     "~/.ssh/main_private_key",
		content:  content,
		bareURL:  bareURL,
	}
}

func setupClientOnlyHome(t *testing.T) *clientFixture {
	t.Helper()
	a, fake, base := newTestApp(t)
	clientHome := config.RoleHome(base, config.RoleClient)
	clientCfg := &config.Client{
		Schema:  config.ConfigSchema,
		Role:    config.RoleClient,
		StoreID: "ks_test_store_id_",
		Host: config.HostInfo{
			ID:           "h_clientonly12345",
			DisplayName:  "machine2",
			IdentityPath: filepath.Join("identities", "host.txt"),
		},
		Repo: config.DefaultRepoInfo("GonzaloAlvarez", "kauket-store"),
	}
	if err := config.SaveClient(clientHome, clientCfg); err != nil {
		t.Fatalf("save client: %v", err)
	}
	return &clientFixture{app: a, fake: fake, home: clientHome}
}

func captureStdout(t *testing.T, fn func()) []byte {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(r)
		done <- data
	}()
	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

func TestGetCreatesFile(t *testing.T) {
	fx := setupEnrolledClient(t, "ssh")
	flags := &getFlags{}
	if err := runGet(context.Background(), fx.app, flags, testSecretID); err != nil {
		t.Fatalf("runGet: %v", err)
	}
	if len(fx.fake.Lines) != 2 {
		t.Fatalf("expected 2 output lines, got %v", fx.fake.Lines)
	}
	if fx.fake.Lines[0] != "syncing store" {
		t.Fatalf("first line %q, want %q", fx.fake.Lines[0], "syncing store")
	}
	if fx.fake.Lines[1] != "creating "+fx.dest {
		t.Fatalf("second line %q, want %q", fx.fake.Lines[1], "creating "+fx.dest)
	}

	expanded := filepath.Join(fx.tempHome, ".ssh", "main_private_key")
	got, err := os.ReadFile(expanded)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != string(fx.content) {
		t.Fatalf("content mismatch: got %q want %q", string(got), string(fx.content))
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(expanded)
		if err != nil {
			t.Fatalf("stat dest: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("file mode: got %o want 0600", fi.Mode().Perm())
		}
		di, err := os.Stat(filepath.Join(fx.tempHome, ".ssh"))
		if err != nil {
			t.Fatalf("stat dir: %v", err)
		}
		if di.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode: got %o want 0700", di.Mode().Perm())
		}
	}
}

func TestGetIdempotentNoChange(t *testing.T) {
	fx := setupEnrolledClient(t, "ssh")
	flags := &getFlags{noSync: true}
	if err := runGet(context.Background(), fx.app, flags, testSecretID); err != nil {
		t.Fatalf("first runGet: %v", err)
	}
	expanded := filepath.Join(fx.tempHome, ".ssh", "main_private_key")
	info1, err := os.Stat(expanded)
	if err != nil {
		t.Fatalf("stat after first install: %v", err)
	}
	mtime1 := info1.ModTime()
	fx.fake.Lines = nil

	if err := runGet(context.Background(), fx.app, flags, testSecretID); err != nil {
		t.Fatalf("second runGet: %v", err)
	}
	if len(fx.fake.Lines) != 1 {
		t.Fatalf("expected 1 line, got %v", fx.fake.Lines)
	}
	if !strings.Contains(fx.fake.Lines[0], "already current") {
		t.Fatalf("expected 'already current' in output, got %q", fx.fake.Lines[0])
	}
	info2, err := os.Stat(expanded)
	if err != nil {
		t.Fatalf("stat after second install: %v", err)
	}
	if !info2.ModTime().Equal(mtime1) {
		t.Fatalf("mtime changed on no-op install: %v -> %v", mtime1, info2.ModTime())
	}
}

func TestGetUnknownNamespaceReturnsExitNotGranted(t *testing.T) {
	fx := setupEnrolledClient(t, "ssh")
	flags := &getFlags{noSync: true}
	err := runGet(context.Background(), fx.app, flags, "other.unknown_secret")
	if err == nil {
		t.Fatalf("expected error on unknown namespace")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitNotGranted {
		t.Fatalf("expected ExitNotGranted (%d), got %d", ExitNotGranted, exitErr.Code)
	}
}

func TestGetSecretMissingFromGrantedNamespace(t *testing.T) {
	fx := setupEnrolledClient(t, "ssh")
	flags := &getFlags{noSync: true}
	err := runGet(context.Background(), fx.app, flags, "ssh.absent_key")
	if err == nil {
		t.Fatalf("expected error on missing secret")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitNotGranted {
		t.Fatalf("expected ExitNotGranted, got %d", exitErr.Code)
	}
	if !strings.Contains(err.Error(), "is not granted to this identity or does not exist") {
		t.Fatalf("unexpected message: %q", err.Error())
	}
}

func TestGetUngrantedNamespaceReturnsExitNotGranted(t *testing.T) {
	adminApp, _, _, clientApp, _, _, _ := v2StoreFixture(t)
	_ = adminApp
	err := runGet(context.Background(), clientApp, &getFlags{noSync: true, stdout: true}, "aws.profile.amzn-wanfe")
	if err == nil {
		t.Fatalf("expected error on ungranted namespace")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitNotGranted {
		t.Fatalf("expected ExitNotGranted, got %d", exitErr.Code)
	}
	if !strings.Contains(err.Error(), "no readable child") {
		t.Fatalf("unexpected message: %q", err.Error())
	}
}

func TestGetStdoutMode(t *testing.T) {
	fx := setupEnrolledClient(t, "ssh")
	flags := &getFlags{noSync: true, stdout: true}
	out := captureStdout(t, func() {
		if err := runGet(context.Background(), fx.app, flags, testSecretID); err != nil {
			t.Fatalf("runGet: %v", err)
		}
	})
	if string(out) != string(fx.content) {
		t.Fatalf("stdout content mismatch: got %q want %q", string(out), string(fx.content))
	}
	for _, line := range fx.fake.Lines {
		if strings.HasPrefix(line, "creating ") {
			t.Fatalf("stdout mode should not print creating line: %q", line)
		}
	}
	expanded := filepath.Join(fx.tempHome, ".ssh", "main_private_key")
	if _, err := os.Stat(expanded); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stdout mode should not install file; got err %v", err)
	}
}

func TestGetUnmanagedDestinationFailsWithoutForce(t *testing.T) {
	fx := setupEnrolledClient(t, "ssh")
	expanded := filepath.Join(fx.tempHome, ".ssh", "main_private_key")
	if err := os.MkdirAll(filepath.Dir(expanded), 0o700); err != nil {
		t.Fatalf("mkdir ssh dir: %v", err)
	}
	if err := os.WriteFile(expanded, []byte("do not overwrite"), 0o600); err != nil {
		t.Fatalf("write pre-existing dest: %v", err)
	}

	flags := &getFlags{noSync: true}
	err := runGet(context.Background(), fx.app, flags, testSecretID)
	if err == nil {
		t.Fatalf("expected error on unmanaged destination")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitInstall {
		t.Fatalf("expected ExitInstall (%d), got %d", ExitInstall, exitErr.Code)
	}
	if !strings.Contains(err.Error(), "destination exists") {
		t.Fatalf("expected 'destination exists', got %q", err.Error())
	}
	got, err := os.ReadFile(expanded)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != "do not overwrite" {
		t.Fatalf("pre-existing file was overwritten: got %q", string(got))
	}
}

func TestGetUnmanagedDestinationWithBackup(t *testing.T) {
	fx := setupEnrolledClient(t, "ssh")
	expanded := filepath.Join(fx.tempHome, ".ssh", "main_private_key")
	if err := os.MkdirAll(filepath.Dir(expanded), 0o700); err != nil {
		t.Fatalf("mkdir ssh dir: %v", err)
	}
	original := []byte("do not overwrite")
	if err := os.WriteFile(expanded, original, 0o600); err != nil {
		t.Fatalf("write pre-existing dest: %v", err)
	}

	flags := &getFlags{noSync: true, backup: true}
	if err := runGet(context.Background(), fx.app, flags, testSecretID); err != nil {
		t.Fatalf("runGet with backup: %v", err)
	}

	got, err := os.ReadFile(expanded)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != string(fx.content) {
		t.Fatalf("new content mismatch: got %q want %q", string(got), string(fx.content))
	}

	entries, err := os.ReadDir(filepath.Dir(expanded))
	if err != nil {
		t.Fatalf("read ssh dir: %v", err)
	}
	var backupPath string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "main_private_key.kauket-bak-") {
			backupPath = filepath.Join(filepath.Dir(expanded), name)
			break
		}
	}
	if backupPath == "" {
		t.Fatalf("expected backup file with prefix main_private_key.kauket-bak-, entries: %v", entries)
	}
	backupContent, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backupContent) != "do not overwrite" {
		t.Fatalf("backup content mismatch: got %q", string(backupContent))
	}
}

func TestGetForceOverwrites(t *testing.T) {
	fx := setupEnrolledClient(t, "ssh")
	expanded := filepath.Join(fx.tempHome, ".ssh", "main_private_key")
	if err := os.MkdirAll(filepath.Dir(expanded), 0o700); err != nil {
		t.Fatalf("mkdir ssh dir: %v", err)
	}
	if err := os.WriteFile(expanded, []byte("do not overwrite"), 0o600); err != nil {
		t.Fatalf("write pre-existing dest: %v", err)
	}

	flags := &getFlags{noSync: true, force: true}
	if err := runGet(context.Background(), fx.app, flags, testSecretID); err != nil {
		t.Fatalf("runGet with force: %v", err)
	}

	got, err := os.ReadFile(expanded)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != string(fx.content) {
		t.Fatalf("content mismatch: got %q want %q", string(got), string(fx.content))
	}
}

func TestGetSymlinkRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test requires posix permissions")
	}
	fx := setupEnrolledClient(t, "ssh")
	expanded := filepath.Join(fx.tempHome, ".ssh", "main_private_key")
	if err := os.MkdirAll(filepath.Dir(expanded), 0o700); err != nil {
		t.Fatalf("mkdir ssh dir: %v", err)
	}
	target := filepath.Join(fx.tempHome, "evil_target")
	if err := os.Symlink(target, expanded); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	flags := &getFlags{noSync: true}
	err := runGet(context.Background(), fx.app, flags, testSecretID)
	if err == nil {
		t.Fatalf("expected error on symlink destination")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitInstall {
		t.Fatalf("expected ExitInstall, got %d", exitErr.Code)
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected 'symlink' in error, got %q", err.Error())
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink target should not be created; got err %v", err)
	}
}
