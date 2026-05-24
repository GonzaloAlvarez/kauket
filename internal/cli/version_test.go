package cli

import (
	"strings"
	"testing"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/buildflags"
	"github.com/gonzaloalvarez/kauket/internal/ui"
)

func TestVersionPrintsKauketAndVersion(t *testing.T) {
	f := &ui.Fake{}
	a := &app.App{UI: f}
	cmd := NewVersion(a)
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE: %v", err)
	}
	if len(f.Lines) != 1 {
		t.Fatalf("want 1 line, got %v", f.Lines)
	}
	got := f.Lines[0]
	if !strings.HasPrefix(got, "kauket ") {
		t.Fatalf("expected line to start with 'kauket ', got %q", got)
	}
	if !strings.Contains(got, buildflags.Version) {
		t.Fatalf("expected line to contain buildflags.Version %q, got %q", buildflags.Version, got)
	}
}
