package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedClock(ts time.Time) func() time.Time {
	return func() time.Time { return ts }
}

func realTempDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	real, err := filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return real
}

func TestInstallFreshFile(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	spec := InstallSpec{
		Destination:   "~/.ssh/main_private_key",
		Mode:          0o600,
		DirectoryMode: 0o700,
	}
	content := []byte("PRIVATE KEY BODY")

	res, err := InstallFile("ssh.main_private_key", content, spec, Options{
		Home: kauketHome,
		Now:  fixedClock(time.Date(2026, 5, 24, 14, 12, 33, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("InstallFile: %v", err)
	}
	if res.Status != StatusCreated {
		t.Fatalf("Status = %v, want StatusCreated", res.Status)
	}

	dest := filepath.Join(tempHome, ".ssh", "main_private_key")
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("content mismatch")
	}

	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %o, want 0600", fi.Mode().Perm())
	}

	di, err := os.Stat(filepath.Join(tempHome, ".ssh"))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %o, want 0700", di.Mode().Perm())
	}

	s, err := LoadState(kauketHome)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	entry, ok := s.Installed["ssh.main_private_key"]
	if !ok {
		t.Fatalf("state missing entry")
	}
	if entry.ExpandedDestination != dest {
		t.Fatalf("ExpandedDestination = %q, want %q", entry.ExpandedDestination, dest)
	}
	if entry.Destination != "~/.ssh/main_private_key" {
		t.Fatalf("Destination = %q", entry.Destination)
	}
	if entry.SHA256 == "" {
		t.Fatalf("SHA256 empty")
	}
	if entry.InstalledAt != "2026-05-24T14:12:33Z" {
		t.Fatalf("InstalledAt = %q", entry.InstalledAt)
	}
}

func TestInstallIdempotentNoChange(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")
	spec := InstallSpec{Destination: "~/.ssh/k", Mode: 0o600, DirectoryMode: 0o700}
	content := []byte("same bytes")

	if _, err := InstallFile("ssh.k", content, spec, Options{Home: kauketHome, Now: fixedClock(time.Now().UTC())}); err != nil {
		t.Fatalf("first install: %v", err)
	}
	dest := filepath.Join(tempHome, ".ssh", "k")
	fi1, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	mt1 := fi1.ModTime()

	time.Sleep(20 * time.Millisecond)

	res, err := InstallFile("ssh.k", content, spec, Options{Home: kauketHome, Now: fixedClock(time.Now().UTC())})
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if res.Status != StatusNoChange {
		t.Fatalf("Status = %v, want StatusNoChange", res.Status)
	}
	fi2, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat 2: %v", err)
	}
	if !fi2.ModTime().Equal(mt1) {
		t.Fatalf("mtime changed: was %v now %v", mt1, fi2.ModTime())
	}
}

func TestInstallReplaceManagedFile(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")
	spec := InstallSpec{Destination: "~/.ssh/k", Mode: 0o600, DirectoryMode: 0o700}

	if _, err := InstallFile("ssh.k", []byte("v1"), spec, Options{Home: kauketHome, Now: fixedClock(time.Now().UTC())}); err != nil {
		t.Fatalf("first install: %v", err)
	}
	res, err := InstallFile("ssh.k", []byte("v2"), spec, Options{Home: kauketHome, Now: fixedClock(time.Now().UTC())})
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if res.Status != StatusReplaced {
		t.Fatalf("Status = %v, want StatusReplaced", res.Status)
	}
	got, err := os.ReadFile(filepath.Join(tempHome, ".ssh", "k"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "v2" {
		t.Fatalf("content = %q, want v2", got)
	}
}

func TestInstallUnmanagedFileFails(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	sshDir := filepath.Join(tempHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dest := filepath.Join(sshDir, "k")
	if err := os.WriteFile(dest, []byte("do not overwrite"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	spec := InstallSpec{Destination: "~/.ssh/k", Mode: 0o600, DirectoryMode: 0o700}
	_, err := InstallFile("ssh.k", []byte("new"), spec, Options{Home: kauketHome, Now: fixedClock(time.Now().UTC())})
	if !errors.Is(err, ErrUnmanagedDestination) {
		t.Fatalf("err = %v, want ErrUnmanagedDestination", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "do not overwrite" {
		t.Fatalf("file modified: %q", got)
	}
}

func TestInstallBackup(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	sshDir := filepath.Join(tempHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dest := filepath.Join(sshDir, "main_private_key")
	original := []byte("do not overwrite")
	if err := os.WriteFile(dest, original, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	ts := time.Date(2026, 5, 24, 14, 12, 33, 0, time.UTC)
	spec := InstallSpec{Destination: "~/.ssh/main_private_key", Mode: 0o600, DirectoryMode: 0o700}
	res, err := InstallFile("ssh.main_private_key", []byte("new"), spec, Options{
		Home:   kauketHome,
		Backup: true,
		Now:    fixedClock(ts),
	})
	if err != nil {
		t.Fatalf("InstallFile: %v", err)
	}
	if res.Status != StatusBackedUpAndReplaced {
		t.Fatalf("Status = %v, want StatusBackedUpAndReplaced", res.Status)
	}
	wantBackup := dest + ".kauket-bak-20260524T141233"
	if res.BackupPath != wantBackup {
		t.Fatalf("BackupPath = %q, want %q", res.BackupPath, wantBackup)
	}
	got, err := os.ReadFile(wantBackup)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("backup content = %q, want %q", got, original)
	}
	newGot, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(newGot) != "new" {
		t.Fatalf("dest content = %q, want new", newGot)
	}
}

func TestInstallForce(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	sshDir := filepath.Join(tempHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dest := filepath.Join(sshDir, "k")
	if err := os.WriteFile(dest, []byte("old"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	spec := InstallSpec{Destination: "~/.ssh/k", Mode: 0o600, DirectoryMode: 0o700}
	res, err := InstallFile("ssh.k", []byte("new"), spec, Options{
		Home:  kauketHome,
		Force: true,
		Now:   fixedClock(time.Now().UTC()),
	})
	if err != nil {
		t.Fatalf("InstallFile: %v", err)
	}
	if res.Status != StatusReplaced {
		t.Fatalf("Status = %v, want StatusReplaced", res.Status)
	}
	if res.BackupPath != "" {
		t.Fatalf("BackupPath = %q, want empty", res.BackupPath)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("content = %q, want new", got)
	}
}

func TestInstallSymlinkAtDestination(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	sshDir := filepath.Join(tempHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	evil := filepath.Join(t.TempDir(), "evil")
	if err := os.Symlink(evil, filepath.Join(sshDir, "k")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	spec := InstallSpec{Destination: "~/.ssh/k", Mode: 0o600, DirectoryMode: 0o700}
	_, err := InstallFile("ssh.k", []byte("new"), spec, Options{Home: kauketHome, Now: fixedClock(time.Now().UTC())})
	var sErr *SymlinkInPathError
	if !errors.As(err, &sErr) {
		t.Fatalf("err = %v, want SymlinkInPathError", err)
	}
	if _, statErr := os.Stat(evil); statErr == nil {
		t.Fatalf("evil file was created")
	}
}

func TestInstallSymlinkAtParent(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	evilDir := filepath.Join(t.TempDir(), "evil-ssh")
	if err := os.MkdirAll(evilDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(evilDir, filepath.Join(tempHome, ".ssh")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	spec := InstallSpec{Destination: "~/.ssh/k", Mode: 0o600, DirectoryMode: 0o700}
	_, err := InstallFile("ssh.k", []byte("new"), spec, Options{Home: kauketHome, Now: fixedClock(time.Now().UTC())})
	var sErr *SymlinkInPathError
	if !errors.As(err, &sErr) {
		t.Fatalf("err = %v, want SymlinkInPathError", err)
	}
	if _, statErr := os.Stat(filepath.Join(evilDir, "k")); statErr == nil {
		t.Fatalf("file written through symlink")
	}
}

func TestInstallSymlinkAtGrandparent(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	evilRoot := filepath.Join(t.TempDir(), "evil-root")
	if err := os.MkdirAll(filepath.Join(evilRoot, "sub"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(evilRoot, filepath.Join(tempHome, "deep")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	spec := InstallSpec{Destination: "~/deep/sub/k", Mode: 0o600, DirectoryMode: 0o700}
	_, err := InstallFile("x.k", []byte("new"), spec, Options{Home: kauketHome, Now: fixedClock(time.Now().UTC())})
	var sErr *SymlinkInPathError
	if !errors.As(err, &sErr) {
		t.Fatalf("err = %v, want SymlinkInPathError", err)
	}
}

func TestInstallPathTraversal(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	cases := []string{
		tempHome + "/sub/../sub/file",
		"/etc/../tmp/foo",
		"../relative/file",
	}
	for _, dest := range cases {
		spec := InstallSpec{Destination: dest, Mode: 0o600, DirectoryMode: 0o700}
		_, err := InstallFile("x.y", []byte("x"), spec, Options{Home: kauketHome, Now: fixedClock(time.Now().UTC())})
		if !errors.Is(err, ErrPathTraversal) {
			t.Fatalf("dest=%q err=%v, want ErrPathTraversal", dest, err)
		}
	}
}

func TestInstallRelativeDestination(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	spec := InstallSpec{Destination: "relative/path/file", Mode: 0o600, DirectoryMode: 0o700}
	_, err := InstallFile("x.y", []byte("x"), spec, Options{Home: kauketHome, Now: fixedClock(time.Now().UTC())})
	if !errors.Is(err, ErrRelativeDest) {
		t.Fatalf("err = %v, want ErrRelativeDest", err)
	}
}

func TestInstallTempFileCleanedOnFailure(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	parent := filepath.Join(tempHome, "sub")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	spec := InstallSpec{Destination: filepath.Join(parent, "k"), Mode: 0o600, DirectoryMode: 0o700}
	_, err := InstallFile("x.k", []byte("x"), spec, Options{Home: kauketHome, Now: fixedClock(time.Now().UTC())})
	if err == nil {
		t.Fatalf("expected failure when parent dir is read-only")
	}
	entries, readErr := os.ReadDir(parent)
	if readErr != nil {
		t.Fatalf("readdir: %v", readErr)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".kauket-") {
			t.Fatalf("temp file not cleaned: %s", e.Name())
		}
	}
}

func TestInstallParentNotDirectory(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	parent := filepath.Join(tempHome, "blocker")
	if err := os.WriteFile(parent, []byte("file not dir"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	spec := InstallSpec{Destination: filepath.Join(parent, "child"), Mode: 0o600, DirectoryMode: 0o700}
	_, err := InstallFile("x.k", []byte("x"), spec, Options{Home: kauketHome, Now: fixedClock(time.Now().UTC())})
	if !errors.Is(err, ErrParentNotDir) {
		t.Fatalf("err = %v, want ErrParentNotDir", err)
	}
}

func TestInstallDoesNotModifyExistingDirMode(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	sshDir := filepath.Join(tempHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(sshDir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	spec := InstallSpec{Destination: "~/.ssh/k", Mode: 0o600, DirectoryMode: 0o700}
	if _, err := InstallFile("ssh.k", []byte("body"), spec, Options{Home: kauketHome, Now: fixedClock(time.Now().UTC())}); err != nil {
		t.Fatalf("InstallFile: %v", err)
	}
	info, err := os.Stat(sshDir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("preexisting dir mode changed: %o", info.Mode().Perm())
	}
}

func TestInstallStaleStateFails(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	sshDir := filepath.Join(tempHome, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dest := filepath.Join(sshDir, "k")
	if err := os.WriteFile(dest, []byte("not what state claims"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := &State{
		Schema: 1,
		Installed: map[string]Entry{
			"ssh.k": {
				Destination:         "~/.ssh/k",
				ExpandedDestination: dest,
				SHA256:              "0000000000000000000000000000000000000000000000000000000000000000",
				InstalledAt:         "2026-05-24T14:12:33Z",
			},
		},
	}
	if err := SaveState(kauketHome, s); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	spec := InstallSpec{Destination: "~/.ssh/k", Mode: 0o600, DirectoryMode: 0o700}
	_, err := InstallFile("ssh.k", []byte("new"), spec, Options{Home: kauketHome, Now: fixedClock(time.Now().UTC())})
	if !errors.Is(err, ErrUnmanagedDestination) {
		t.Fatalf("err = %v, want ErrUnmanagedDestination for stale state", err)
	}
}
