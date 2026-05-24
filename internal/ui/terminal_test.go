package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestTerminalPrintln(t *testing.T) {
	var out bytes.Buffer
	tr := &Terminal{Stdout: &out, Stderr: &bytes.Buffer{}, Stdin: strings.NewReader("")}
	tr.Println("hello")
	if out.String() != "hello\n" {
		t.Fatalf("got %q", out.String())
	}
}

func TestTerminalErrorfPrefixesError(t *testing.T) {
	var err bytes.Buffer
	tr := &Terminal{Stdout: &bytes.Buffer{}, Stderr: &err, Stdin: strings.NewReader("")}
	tr.Errorf("something %s", "bad")
	if err.String() != "error: something bad\n" {
		t.Fatalf("got %q", err.String())
	}
}

func TestTerminalConfirmYes(t *testing.T) {
	var out bytes.Buffer
	tr := &Terminal{Stdout: &out, Stderr: &bytes.Buffer{}, Stdin: strings.NewReader("y\n")}
	ok, err := tr.Confirm("proceed?")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ok {
		t.Fatalf("want true for 'y'")
	}
	if !strings.Contains(out.String(), "proceed? [y/N] ") {
		t.Fatalf("prompt missing: %q", out.String())
	}
}

func TestTerminalConfirmYesWord(t *testing.T) {
	tr := &Terminal{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Stdin: strings.NewReader("YES\n")}
	ok, err := tr.Confirm("proceed?")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ok {
		t.Fatalf("want true for 'YES'")
	}
}

func TestTerminalConfirmNoOnEmpty(t *testing.T) {
	tr := &Terminal{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Stdin: strings.NewReader("\n")}
	ok, err := tr.Confirm("proceed?")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Fatalf("want false on empty input")
	}
}

func TestTerminalPromptf(t *testing.T) {
	var out bytes.Buffer
	tr := &Terminal{Stdout: &out, Stderr: &bytes.Buffer{}, Stdin: strings.NewReader("  answer  \n")}
	got, err := tr.Promptf("name (%s)? ", "default")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "answer" {
		t.Fatalf("want trimmed 'answer', got %q", got)
	}
	if !strings.Contains(out.String(), "name (default)? ") {
		t.Fatalf("prompt missing: %q", out.String())
	}
}

func TestFakeCaptures(t *testing.T) {
	f := &Fake{ConfirmReply: true, PromptReply: "x"}
	f.Println("line1")
	f.Errorf("oops %d", 7)
	ok, _ := f.Confirm("?")
	if !ok {
		t.Fatalf("fake confirm should return true")
	}
	got, _ := f.Promptf("?")
	if got != "x" {
		t.Fatalf("got %q", got)
	}
	if len(f.Lines) != 1 || f.Lines[0] != "line1" {
		t.Fatalf("lines: %v", f.Lines)
	}
	if len(f.Errors) != 1 || f.Errors[0] != "oops 7" {
		t.Fatalf("errors: %v", f.Errors)
	}
}
