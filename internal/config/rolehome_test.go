package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoleHome(t *testing.T) {
	if got := RoleHome("/base", RoleAdmin); got != filepath.Join("/base", "admin") {
		t.Fatalf("RoleHome(admin) = %q", got)
	}
	if got := RoleHome("/base", RoleClient); got != filepath.Join("/base", "client") {
		t.Fatalf("RoleHome(client) = %q", got)
	}
}

func TestResolveRoleHome_Canonical(t *testing.T) {
	base := setupHome(t)
	if err := SaveAdmin(RoleHome(base, RoleAdmin), adminFixture()); err != nil {
		t.Fatalf("SaveAdmin: %v", err)
	}
	home, exists, err := ResolveRoleHome(base, RoleAdmin)
	if err != nil {
		t.Fatalf("ResolveRoleHome: %v", err)
	}
	if !exists {
		t.Fatalf("exists = false, want true")
	}
	if home != RoleHome(base, RoleAdmin) {
		t.Fatalf("home = %q, want %q", home, RoleHome(base, RoleAdmin))
	}
}

func TestResolveRoleHome_LegacyRoot(t *testing.T) {
	base := setupHome(t)
	if err := SaveClient(base, clientFixture()); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	_, _, err := ResolveRoleHome(base, RoleClient)
	if err == nil {
		t.Fatalf("ResolveRoleHome: want legacy-layout error, got nil")
	}
	if !strings.Contains(err.Error(), "legacy root-layout home") {
		t.Fatalf("ResolveRoleHome error = %q, want legacy root-layout hint", err)
	}
}

func TestResolveRoleHome_LegacyRootOtherRoleNotFound(t *testing.T) {
	base := setupHome(t)
	if err := SaveClient(base, clientFixture()); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	home, exists, err := ResolveRoleHome(base, RoleAdmin)
	if err != nil {
		t.Fatalf("ResolveRoleHome: %v", err)
	}
	if exists {
		t.Fatalf("exists = true, want false (root is client)")
	}
	if home != RoleHome(base, RoleAdmin) {
		t.Fatalf("home = %q, want canonical target %q", home, RoleHome(base, RoleAdmin))
	}
}

func TestResolveRoleHome_SubdirWinsOverRoot(t *testing.T) {
	base := setupHome(t)
	if err := SaveAdmin(base, adminFixture()); err != nil {
		t.Fatalf("SaveAdmin(root): %v", err)
	}
	if err := SaveAdmin(RoleHome(base, RoleAdmin), adminFixture()); err != nil {
		t.Fatalf("SaveAdmin(subdir): %v", err)
	}
	home, exists, err := ResolveRoleHome(base, RoleAdmin)
	if err != nil {
		t.Fatalf("ResolveRoleHome: %v", err)
	}
	if !exists || home != RoleHome(base, RoleAdmin) {
		t.Fatalf("home = %q exists = %v, want subdir wins", home, exists)
	}
}

func TestResolveRoleHome_WrongRoleInSubdirErrors(t *testing.T) {
	base := setupHome(t)
	if err := SaveClient(RoleHome(base, RoleAdmin), clientFixture()); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	_, _, err := ResolveRoleHome(base, RoleAdmin)
	if err == nil {
		t.Fatalf("ResolveRoleHome = nil error, want corrupt-layout error")
	}
	if !strings.Contains(err.Error(), "declares role") {
		t.Fatalf("err = %q, want declares-role message", err)
	}
}

func TestResolveRoleHome_MalformedSubdirConfig(t *testing.T) {
	base := setupHome(t)
	sub := RoleHome(base, RoleClient)
	if err := os.MkdirAll(sub, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(ConfigPath(sub), []byte("{not json"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := ResolveRoleHome(base, RoleClient); err == nil {
		t.Fatalf("ResolveRoleHome on malformed = nil, want error")
	}
}

func TestResolveRoleHome_Empty(t *testing.T) {
	base := setupHome(t)
	home, exists, err := ResolveRoleHome(base, RoleClient)
	if err != nil {
		t.Fatalf("ResolveRoleHome: %v", err)
	}
	if exists {
		t.Fatalf("exists = true, want false")
	}
	if home != RoleHome(base, RoleClient) {
		t.Fatalf("home = %q, want %q", home, RoleHome(base, RoleClient))
	}
}

func TestInstalledRoles_Order(t *testing.T) {
	base := setupHome(t)
	if err := SaveClient(RoleHome(base, RoleClient), clientFixture()); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	if err := SaveAdmin(RoleHome(base, RoleAdmin), adminFixture()); err != nil {
		t.Fatalf("SaveAdmin: %v", err)
	}
	roles, err := InstalledRoles(base)
	if err != nil {
		t.Fatalf("InstalledRoles: %v", err)
	}
	if len(roles) != 2 || roles[0] != RoleAdmin || roles[1] != RoleClient {
		t.Fatalf("roles = %v, want [admin client]", roles)
	}
}

func TestInstalledRoles_LegacyMixed(t *testing.T) {
	base := setupHome(t)
	if err := SaveAdmin(base, adminFixture()); err != nil {
		t.Fatalf("SaveAdmin(root): %v", err)
	}
	if err := SaveClient(RoleHome(base, RoleClient), clientFixture()); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	if _, err := InstalledRoles(base); err == nil {
		t.Fatalf("InstalledRoles: want legacy-layout error, got nil")
	}
}

func TestInstalledRoles_Empty(t *testing.T) {
	base := setupHome(t)
	roles, err := InstalledRoles(base)
	if err != nil {
		t.Fatalf("InstalledRoles: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("roles = %v, want empty", roles)
	}
}
