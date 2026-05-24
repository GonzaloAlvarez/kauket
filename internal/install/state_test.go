package install

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadStateMissing(t *testing.T) {
	home := t.TempDir()
	s, err := LoadState(home)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if s.Schema != 1 {
		t.Fatalf("Schema = %d, want 1", s.Schema)
	}
	if s.Installed == nil {
		t.Fatalf("Installed map should be initialized")
	}
	if len(s.Installed) != 0 {
		t.Fatalf("Installed should be empty, got %d", len(s.Installed))
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	home := t.TempDir()
	in := &State{
		Schema: 1,
		Installed: map[string]Entry{
			"ssh.main_private_key": {
				Destination:         "~/.ssh/main_private_key",
				ExpandedDestination: "/home/u/.ssh/main_private_key",
				SHA256:              "abc123",
				InstalledAt:         "2026-05-24T14:12:33Z",
			},
			"aws.primary_account.key_file": {
				Destination:         "~/.aws/credentials",
				ExpandedDestination: "/home/u/.aws/credentials",
				SHA256:              "deadbeef",
				InstalledAt:         "2026-05-24T15:00:00Z",
			},
		},
	}
	if err := SaveState(home, in); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	out, err := LoadState(home)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if !reflect.DeepEqual(in.Installed, out.Installed) {
		t.Fatalf("round-trip mismatch:\n in=%+v\nout=%+v", in.Installed, out.Installed)
	}
	if out.Schema != 1 {
		t.Fatalf("Schema = %d, want 1", out.Schema)
	}
}

func TestSaveStateFileMode(t *testing.T) {
	home := t.TempDir()
	s := &State{
		Schema:    1,
		Installed: map[string]Entry{"x.y": {Destination: "~/x", ExpandedDestination: "/home/u/x", SHA256: "h", InstalledAt: "t"}},
	}
	if err := SaveState(home, s); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	info, err := os.Stat(filepath.Join(home, "state", "installed.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %o, want 0600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Join(home, "state"))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %o, want 0700", dirInfo.Mode().Perm())
	}
}

func TestLoadStateMalformed(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "state"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "state", "installed.json"), []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadState(home); err == nil {
		t.Fatalf("expected error on malformed state")
	}
}
