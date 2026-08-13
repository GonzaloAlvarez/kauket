package install

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func c2Opts(home string) Options {
	return Options{Home: home, Now: fixedClock(time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC))}
}

func TestInstallRejectsDestinationOutsideHome(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	outside := filepath.Join(realTempDir(t), "evil.txt")
	spec := InstallSpec{Destination: outside, Mode: 0o600, DirectoryMode: 0o700}
	_, err := InstallFile("x.y", []byte("secret"), spec, c2Opts(kauketHome))
	if !errors.Is(err, ErrDestinationOutsideRoot) {
		t.Fatalf("err = %v, want ErrDestinationOutsideRoot", err)
	}
	if _, statErr := os.Stat(outside); statErr == nil {
		t.Fatalf("file was written outside home despite rejection")
	}
}

func TestInstallRejectsDeniedTarget(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	spec := InstallSpec{Destination: "~/.bashrc", Mode: 0o600, DirectoryMode: 0o700}
	_, err := InstallFile("x.y", []byte("secret"), spec, c2Opts(kauketHome))
	if !errors.Is(err, ErrDeniedTarget) {
		t.Fatalf("err = %v, want ErrDeniedTarget", err)
	}
}

func TestInstallRejectsLooseModes(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	cases := []struct {
		name string
		spec InstallSpec
	}{
		{"world-readable file", InstallSpec{Destination: "~/.ssh/id", Mode: 0o644, DirectoryMode: 0o700}},
		{"world-writable file", InstallSpec{Destination: "~/.ssh/id", Mode: 0o666, DirectoryMode: 0o700}},
		{"setuid file", InstallSpec{Destination: "~/.ssh/id", Mode: 0o4755, DirectoryMode: 0o700}},
		{"world dir", InstallSpec{Destination: "~/data/id", Mode: 0o600, DirectoryMode: 0o777}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := InstallFile("x.y", []byte("secret"), tc.spec, c2Opts(kauketHome))
			if !errors.Is(err, ErrUnsafeMode) {
				t.Fatalf("err = %v, want ErrUnsafeMode", err)
			}
		})
	}
}

func TestInstallAllowsOptOut(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	otherRoot := realTempDir(t)
	dest := filepath.Join(otherRoot, "sub", "cfg")
	opts := c2Opts(kauketHome)
	opts.AllowedRoots = []string{otherRoot}
	opts.AllowLooseModes = true
	spec := InstallSpec{Destination: dest, Mode: 0o644, DirectoryMode: 0o700}
	if _, err := InstallFile("x.y", []byte("secret"), spec, opts); err != nil {
		t.Fatalf("opt-out install failed: %v", err)
	}
	if _, statErr := os.Stat(dest); statErr != nil {
		t.Fatalf("opt-out destination not written: %v", statErr)
	}
}

func TestInstallInHomeStillWorks(t *testing.T) {
	tempHome := realTempDir(t)
	t.Setenv("HOME", tempHome)
	kauketHome := filepath.Join(tempHome, ".config", "kauket")

	spec := InstallSpec{Destination: "~/.ssh/id", Mode: 0o600, DirectoryMode: 0o700}
	if _, err := InstallFile("ssh.id", []byte("secret"), spec, c2Opts(kauketHome)); err != nil {
		t.Fatalf("in-home install failed: %v", err)
	}
	assertPerm(t, filepath.Join(tempHome, ".ssh", "id"), 0o600)
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), want)
	}
}
