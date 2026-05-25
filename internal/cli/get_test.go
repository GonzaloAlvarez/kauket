package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	gogit "github.com/go-git/go-git/v5"
	gogitcfg "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/model"
	"github.com/gonzaloalvarez/kauket/internal/ui"
)

const testSecretID = "ssh.main_private_key"

const testSecretContent = "PRIVATE KEY BODY"

func mustGenerateIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := agebox.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func writeIdentityToFile(t *testing.T, path string, id *age.X25519Identity) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir identity dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
}

type clientFixture struct {
	app      *app.App
	fake     *ui.Fake
	home     string
	hostID   string
	dest     string
	content  []byte
	tempHome string
	bareURL  string
}

func setupClient(t *testing.T) (*clientFixture, *age.X25519Identity, *age.X25519Identity) {
	t.Helper()
	tempHome := t.TempDir()
	resolved, err := filepath.EvalSymlinks(tempHome)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	tempHome = resolved
	t.Setenv("HOME", tempHome)

	kauketHome := filepath.Join(tempHome, ".config", "kauket")
	if err := os.MkdirAll(kauketHome, 0o700); err != nil {
		t.Fatalf("mkdir kauket home: %v", err)
	}

	bareURL := bareRepo(t)

	fake := &ui.Fake{}
	a := &app.App{
		UI:   fake,
		Home: kauketHome,
		Now:  func() time.Time { return time.Date(2026, 5, 24, 14, 12, 33, 0, time.UTC) },
	}

	hostIdentity := mustGenerateIdentity(t)
	adminIdentity := mustGenerateIdentity(t)
	hostIdentityPath := filepath.Join(kauketHome, "identities", "host.txt")
	writeIdentityToFile(t, hostIdentityPath, hostIdentity)

	hostID := model.NewHostID()
	clientCfg := &config.Client{
		Schema:  config.ConfigSchema,
		Role:    config.RoleClient,
		StoreID: "ks_test_store_id_",
		Host: config.HostInfo{
			ID:            hostID,
			DisplayName:   "machine2",
			IdentityPath:  filepath.Join("identities", "host.txt"),
			DeployKeyPath: filepath.Join("git", "deploy_key"),
		},
		Repo: config.RepoInfo{
			Owner:         "GonzaloAlvarez",
			Name:          "kauket-store",
			RemoteHTTPS:   bareURL,
			DefaultBranch: "main",
		},
		CommitAuthor: config.CommitAuthor{Name: "kauket-" + hostID, Email: "kauket@" + hostID + ".local"},
	}
	if err := config.SaveClient(kauketHome, clientCfg); err != nil {
		t.Fatalf("save client: %v", err)
	}

	return &clientFixture{
		app:      a,
		fake:     fake,
		home:     kauketHome,
		hostID:   hostID,
		dest:     "~/.ssh/main_private_key",
		content:  []byte(testSecretContent),
		tempHome: tempHome,
		bareURL:  bareURL,
	}, hostIdentity, adminIdentity
}

func encryptBundleFor(t *testing.T, fx *clientFixture, hostIdentity, adminIdentity *age.X25519Identity, secrets map[string]model.BundleSecret) []byte {
	t.Helper()
	b := model.Bundle{
		Schema:           1,
		StoreID:          "ks_test_store_id_",
		HostID:           fx.hostID,
		GeneratedAt:      "2026-05-24T00:00:00Z",
		BundleGeneration: 1,
		Secrets:          secrets,
	}
	hostRecip := agebox.X25519RecipientProvider{Strings: []string{hostIdentity.Recipient().String()}}
	adminRecips := agebox.X25519RecipientProvider{Strings: []string{adminIdentity.Recipient().String()}}
	ct, err := bundle.EncodeHostBundle(b, hostRecip, adminRecips)
	if err != nil {
		t.Fatalf("encode bundle: %v", err)
	}
	return ct
}

func defaultBundleSecrets(fx *clientFixture) map[string]model.BundleSecret {
	return map[string]model.BundleSecret{
		testSecretID: {
			Kind:          "file",
			Install:       model.InstallSpec{Destination: fx.dest, Mode: "0600", DirectoryMode: "0700"},
			ContentBase64: base64.StdEncoding.EncodeToString(fx.content),
			SHA256:        "deadbeef",
		},
	}
}

func setupClientWithLocalBundle(t *testing.T) *clientFixture {
	t.Helper()
	fx, hostIdentity, adminIdentity := setupClient(t)
	ct := encryptBundleFor(t, fx, hostIdentity, adminIdentity, defaultBundleSecrets(fx))
	writeLocalBundle(t, fx.home, fx.hostID, ct)
	return fx
}

func setupClientWithRemoteBundle(t *testing.T) *clientFixture {
	t.Helper()
	fx, hostIdentity, adminIdentity := setupClient(t)
	ct := encryptBundleFor(t, fx, hostIdentity, adminIdentity, defaultBundleSecrets(fx))
	pushBundleToBare(t, fx.bareURL, fx.hostID, ct)
	return fx
}

func setupClientNoBundle(t *testing.T) *clientFixture {
	t.Helper()
	fx, _, _ := setupClient(t)
	return fx
}

func writeLocalBundle(t *testing.T, kauketHome, hostID string, ct []byte) {
	t.Helper()
	bundlePath := filepath.Join(kauketHome, "repo", "bundles", hostID+".age")
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o700); err != nil {
		t.Fatalf("mkdir bundles: %v", err)
	}
	if err := os.WriteFile(bundlePath, ct, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
}

func pushBundleToBare(t *testing.T, bareURL, hostID string, ct []byte) {
	t.Helper()
	workDir := t.TempDir()
	if err := os.RemoveAll(workDir); err != nil {
		t.Fatalf("clean work dir: %v", err)
	}
	repo, err := gogit.PlainInit(workDir, false)
	if err != nil {
		t.Fatalf("init working: %v", err)
	}
	head := plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.NewBranchReferenceName("main"))
	if err := repo.Storer.SetReference(head); err != nil {
		t.Fatalf("set HEAD: %v", err)
	}
	if _, err := repo.CreateRemote(&gogitcfg.RemoteConfig{
		Name: "origin",
		URLs: []string{bareURL},
	}); err != nil {
		t.Fatalf("create remote: %v", err)
	}
	bundleDir := filepath.Join(workDir, "bundles")
	if err := os.MkdirAll(bundleDir, 0o700); err != nil {
		t.Fatalf("mkdir bundles dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, hostID+".age"), ct, 0o600); err != nil {
		t.Fatalf("write bundle in working: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if err := wt.AddWithOptions(&gogit.AddOptions{All: true}); err != nil {
		t.Fatalf("add: %v", err)
	}
	sig := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}
	if _, err := wt.Commit("kauket: test bundle", &gogit.CommitOptions{Author: sig, Committer: sig}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := repo.Push(&gogit.PushOptions{
		RemoteName: "origin",
		RefSpecs:   []gogitcfg.RefSpec{gogitcfg.RefSpec("refs/heads/main:refs/heads/main")},
	}); err != nil {
		t.Fatalf("push: %v", err)
	}
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
	fx := setupClientWithRemoteBundle(t)
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
	if string(got) != testSecretContent {
		t.Fatalf("content mismatch: got %q want %q", string(got), testSecretContent)
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
	fx := setupClientWithLocalBundle(t)
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

func TestGetMissingBundleReturnsExitNotGranted(t *testing.T) {
	fx := setupClientNoBundle(t)
	flags := &getFlags{noSync: true}
	err := runGet(context.Background(), fx.app, flags, testSecretID)
	if err == nil {
		t.Fatalf("expected error on missing bundle")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.Code != ExitNotGranted {
		t.Fatalf("expected ExitNotGranted (%d), got %d", ExitNotGranted, exitErr.Code)
	}
	if !strings.Contains(err.Error(), "no approved bundle found") {
		t.Fatalf("expected 'no approved bundle found', got %q", err.Error())
	}
}

func TestGetSecretNotInBundle(t *testing.T) {
	fx := setupClientWithLocalBundle(t)
	flags := &getFlags{noSync: true}
	err := runGet(context.Background(), fx.app, flags, "aws.something_unknown")
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
	if !strings.Contains(err.Error(), "is not granted to this machine") {
		t.Fatalf("expected 'is not granted to this machine', got %q", err.Error())
	}
}

func TestGetStdoutMode(t *testing.T) {
	fx := setupClientWithLocalBundle(t)
	flags := &getFlags{noSync: true, stdout: true}
	out := captureStdout(t, func() {
		if err := runGet(context.Background(), fx.app, flags, testSecretID); err != nil {
			t.Fatalf("runGet: %v", err)
		}
	})
	if string(out) != testSecretContent {
		t.Fatalf("stdout content mismatch: got %q want %q", string(out), testSecretContent)
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
	fx := setupClientWithLocalBundle(t)
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
	fx := setupClientWithLocalBundle(t)
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
	if string(got) != testSecretContent {
		t.Fatalf("new content mismatch: got %q want %q", string(got), testSecretContent)
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
	fx := setupClientWithLocalBundle(t)
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
	if string(got) != testSecretContent {
		t.Fatalf("content mismatch: got %q want %q", string(got), testSecretContent)
	}
}

func TestGetSymlinkRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test requires posix permissions")
	}
	fx := setupClientWithLocalBundle(t)
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
