package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPinsLoadMissingReturnsEmpty(t *testing.T) {
	p, err := LoadPins(filepath.Join(t.TempDir(), "state", "pins.json"))
	if err != nil {
		t.Fatalf("LoadPins: %v", err)
	}
	if p.Schema != pinsSchema || len(p.NodeVersions) != 0 || p.StoreID != "" {
		t.Fatalf("pins = %+v", p)
	}
}

func TestPinsRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "pins.json")
	in := &Pins{
		StoreID:             "ks_pinstest12345678",
		TrustAnchors:        []TrustAnchor{{IID: "i_a", SignPubkey: "ssh-ed25519 AAA"}},
		RecoverySignPubkeys: []string{"ssh-ed25519 BBB"},
		NodeVersions:        map[string]int{"n_root": 7, "n_aws": 3},
		UpdatedAt:           "2026-07-28T00:00:00Z",
	}
	if err := SavePins(path, in); err != nil {
		t.Fatalf("SavePins: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("pins mode = %o, want 0600", info.Mode().Perm())
	}
	out, err := LoadPins(path)
	if err != nil {
		t.Fatalf("LoadPins: %v", err)
	}
	if out.StoreID != in.StoreID || out.NodeVersions["n_root"] != 7 || out.NodeVersions["n_aws"] != 3 {
		t.Fatalf("pins = %+v", out)
	}
	keys := out.PinnedSignKeys()
	if len(keys) != 2 || keys[0] != "ssh-ed25519 AAA" || keys[1] != "ssh-ed25519 BBB" {
		t.Fatalf("pinned keys = %v", keys)
	}
}

func TestPinsMalformedErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadPins(path); err == nil {
		t.Fatalf("expected parse error")
	}
}
