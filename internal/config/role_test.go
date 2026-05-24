package config

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequireRole_AdminOnAdmin(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "kauket")
	t.Setenv("KAUKET_HOME", home)
	if _, err := EnsureHome(); err != nil {
		t.Fatalf("EnsureHome: %v", err)
	}
	if err := SaveAdmin(home, adminFixture()); err != nil {
		t.Fatalf("SaveAdmin: %v", err)
	}
	if err := RequireRole(home, RoleAdmin); err != nil {
		t.Fatalf("RequireRole(admin) on admin = %v, want nil", err)
	}
}

func TestRequireRole_AdminOnClient(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "kauket")
	t.Setenv("KAUKET_HOME", home)
	if _, err := EnsureHome(); err != nil {
		t.Fatalf("EnsureHome: %v", err)
	}
	if err := SaveClient(home, clientFixture()); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	err := RequireRole(home, RoleAdmin)
	if err == nil {
		t.Fatalf("RequireRole(admin) on client = nil, want WrongRoleError")
	}
	var wre *WrongRoleError
	if !errors.As(err, &wre) {
		t.Fatalf("err type = %T, want *WrongRoleError", err)
	}
	if wre.Want != RoleAdmin {
		t.Errorf("Want = %q, want %q", wre.Want, RoleAdmin)
	}
	if wre.Got != RoleClient {
		t.Errorf("Got = %q, want %q", wre.Got, RoleClient)
	}
	want := "kauket: this command requires admin role on this machine; current role is client"
	if wre.Error() != want {
		t.Errorf("Error() = %q, want %q", wre.Error(), want)
	}
}

func TestRequireRole_ClientOnNoConfig(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "kauket")
	t.Setenv("KAUKET_HOME", home)
	if _, err := EnsureHome(); err != nil {
		t.Fatalf("EnsureHome: %v", err)
	}
	err := RequireRole(home, RoleClient)
	if err == nil {
		t.Fatalf("RequireRole(client) on missing = nil, want wrapped error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "no kauket store configured here") {
		t.Errorf("err = %q, want 'no kauket store configured here'", msg)
	}
	if !strings.Contains(msg, "kauket init") || !strings.Contains(msg, "kauket enroll") {
		t.Errorf("err = %q, expected init/enroll hint", msg)
	}
}

func TestRequireRole_ClientOnClient(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "kauket")
	t.Setenv("KAUKET_HOME", home)
	if _, err := EnsureHome(); err != nil {
		t.Fatalf("EnsureHome: %v", err)
	}
	if err := SaveClient(home, clientFixture()); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}
	if err := RequireRole(home, RoleClient); err != nil {
		t.Fatalf("RequireRole(client) on client = %v, want nil", err)
	}
}
