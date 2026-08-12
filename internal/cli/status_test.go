package cli

import (
	"testing"
)

func TestStatusUninitialized(t *testing.T) {
	a, fake, _ := newTestApp(t)
	if err := runStatus(a, ""); err != nil {
		t.Fatalf("runStatus: %v", err)
	}
	if len(fake.Lines) != 1 || fake.Lines[0] != "role: uninitialized" {
		t.Fatalf("want 'role: uninitialized', got %v", fake.Lines)
	}
}

func TestStatusAdminAfterInit(t *testing.T) {
	a, fake, _ := initAdminFixture(t)
	if err := runStatus(a, ""); err != nil {
		t.Fatalf("status: %v", err)
	}
	wantLines := []string{
		"role: admin",
		"store: GonzaloAlvarez/kauket-store",
		"schema: 2",
		"nodes readable: 1",
		"entries readable: 0",
	}
	if len(fake.Lines) != len(wantLines) {
		t.Fatalf("expected %d lines, got %d: %v", len(wantLines), len(fake.Lines), fake.Lines)
	}
	for i, want := range wantLines {
		if fake.Lines[i] != want {
			t.Fatalf("line %d: want %q got %q", i, want, fake.Lines[i])
		}
	}
}

func TestStatusClient(t *testing.T) {
	fx := setupEnrolledClient(t, "ssh")
	if err := runStatus(fx.app, ""); err != nil {
		t.Fatalf("status: %v", err)
	}
	wantLines := []string{
		"role: client",
		"store: GonzaloAlvarez/kauket-store",
		"schema: 2",
		"nodes readable: 2",
		"entries readable: 1",
	}
	if len(fx.fake.Lines) != len(wantLines) {
		t.Fatalf("expected %d lines, got %d: %v", len(wantLines), len(fx.fake.Lines), fx.fake.Lines)
	}
	for i, want := range wantLines {
		if fx.fake.Lines[i] != want {
			t.Fatalf("line %d: want %q got %q", i, want, fx.fake.Lines[i])
		}
	}
}
