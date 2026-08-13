package cli

import (
	"strings"
	"testing"
)

func statusLinesWithoutFingerprint(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.HasPrefix(l, "trust-anchor fingerprint:") {
			continue
		}
		out = append(out, l)
	}
	return out
}

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
		"schema: 3 (sealed)",
		"nodes readable: 1",
		"entries readable: 0",
	}
	got := statusLinesWithoutFingerprint(fake.Lines)
	if len(got) != len(wantLines) {
		t.Fatalf("expected %d lines, got %d: %v", len(wantLines), len(got), fake.Lines)
	}
	for i, want := range wantLines {
		if got[i] != want {
			t.Fatalf("line %d: want %q got %q", i, want, got[i])
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
		"schema: 3 (sealed)",
		"nodes readable: 2",
		"entries readable: 1",
	}
	got := statusLinesWithoutFingerprint(fx.fake.Lines)
	if len(got) != len(wantLines) {
		t.Fatalf("expected %d lines, got %d: %v", len(wantLines), len(got), fx.fake.Lines)
	}
	for i, want := range wantLines {
		if got[i] != want {
			t.Fatalf("line %d: want %q got %q", i, want, got[i])
		}
	}
}
