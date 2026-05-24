package githubauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

type MockRun struct {
	Stdout []byte
	Stderr []byte
	Err    error
}

type MockShell struct {
	LookPathErr error
	LookPathOut string
	RunOutputs  map[string]MockRun
	Calls       []string
}

func (m *MockShell) LookPath(name string) (string, error) {
	if m.LookPathErr != nil {
		return "", m.LookPathErr
	}
	if m.LookPathOut != "" {
		return m.LookPathOut, nil
	}
	return "/usr/local/bin/" + name, nil
}

func (m *MockShell) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	key := joinCmd(name, args)
	m.Calls = append(m.Calls, key)
	r, ok := m.RunOutputs[key]
	if !ok {
		return nil, nil, fmt.Errorf("mockshell: no canned response for %q", key)
	}
	return r.Stdout, r.Stderr, r.Err
}

func joinCmd(name string, args []string) string {
	if len(args) == 0 {
		return name
	}
	return name + " " + strings.Join(args, " ")
}

const sampleAuthStatusOK = `github.com
  ✓ Logged in to github.com account GonzaloAlvarez (keyring)
  - Active account: true
  - Git operations protocol: https
  - Token: gho_************************************
  - Token scopes: 'gist', 'read:org', 'repo', 'admin:public_key'

  ✓ Logged in to github.com account other (keyring)
  - Active account: false
  - Git operations protocol: https
  - Token: gho_************************************
  - Token scopes: 'repo'
`

const sampleAuthStatusOnlyRepo = `github.com
  ✓ Logged in to github.com account GonzaloAlvarez (keyring)
  - Active account: true
  - Git operations protocol: https
  - Token: gho_************************************
  - Token scopes: 'gist', 'read:org', 'repo'
`

const sampleAuthStatusFailMsg = `You are not logged into any GitHub hosts. To log in, run: gh auth login`

const fakeGHToken = "FAKE_TEST_TOKEN_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestGHCLIProviderNotInstalled(t *testing.T) {
	sh := &MockShell{LookPathErr: exec.ErrNotFound}
	p := &GHCLIProvider{Shell: sh}
	tok, err := p.Token(context.Background(), []string{"repo"})
	if tok != "" {
		t.Fatalf("expected empty token, got %q", tok)
	}
	if !errors.Is(err, ErrGHNotInstalled) {
		t.Fatalf("expected ErrGHNotInstalled, got %v", err)
	}
}

func TestGHCLIProviderAuthStatusFails(t *testing.T) {
	sh := &MockShell{
		RunOutputs: map[string]MockRun{
			"gh auth status": {
				Stderr: []byte(sampleAuthStatusFailMsg),
				Err:    &exec.ExitError{},
			},
		},
	}
	p := &GHCLIProvider{Shell: sh}
	tok, err := p.Token(context.Background(), []string{"repo"})
	if tok != "" {
		t.Fatalf("expected empty token, got %q", tok)
	}
	if !errors.Is(err, ErrGHNotAuthenticated) {
		t.Fatalf("expected ErrGHNotAuthenticated, got %v", err)
	}
}

func TestGHCLIProviderNotLoggedIntoGitHubDotCom(t *testing.T) {
	out := `git.taservs.net
  ✓ Logged in to git.taservs.net account galvarez (keyring)
  - Active account: true
  - Token scopes: 'repo'
`
	sh := &MockShell{
		RunOutputs: map[string]MockRun{
			"gh auth status": {Stdout: []byte(out)},
		},
	}
	p := &GHCLIProvider{Shell: sh}
	tok, err := p.Token(context.Background(), []string{"repo"})
	if tok != "" {
		t.Fatalf("expected empty token, got %q", tok)
	}
	if !errors.Is(err, ErrGHNotAuthenticated) {
		t.Fatalf("expected ErrGHNotAuthenticated, got %v", err)
	}
}

func TestGHCLIProviderSufficientScopesReturnsToken(t *testing.T) {
	sh := &MockShell{
		RunOutputs: map[string]MockRun{
			"gh auth status": {Stdout: []byte(sampleAuthStatusOK)},
			"gh auth token":  {Stdout: []byte(fakeGHToken + "\n")},
		},
	}
	p := &GHCLIProvider{Shell: sh}
	tok, err := p.Token(context.Background(), []string{"repo", "admin:public_key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != fakeGHToken {
		t.Fatalf("unexpected token; want %q got %q", fakeGHToken, tok)
	}
}

func TestGHCLIProviderInsufficientScopes(t *testing.T) {
	sh := &MockShell{
		RunOutputs: map[string]MockRun{
			"gh auth status": {Stdout: []byte(sampleAuthStatusOnlyRepo)},
			"gh auth token":  {Stdout: []byte(fakeGHToken + "\n")},
		},
	}
	p := &GHCLIProvider{Shell: sh}
	tok, err := p.Token(context.Background(), []string{"repo", "admin:public_key"})
	if tok != "" {
		t.Fatalf("expected empty token, got %q", tok)
	}
	if !errors.Is(err, ErrInsufficientScopes) {
		t.Fatalf("expected ErrInsufficientScopes, got %v", err)
	}
	var ise *InsufficientScopesError
	if !errors.As(err, &ise) {
		t.Fatalf("expected *InsufficientScopesError, got %T", err)
	}
	got := append([]string{}, ise.Missing...)
	sort.Strings(got)
	want := []string{"admin:public_key"}
	if !equalStrings(got, want) {
		t.Fatalf("missing scopes = %v, want %v", got, want)
	}
	for _, call := range sh.Calls {
		if call == "gh auth token" {
			t.Fatalf("gh auth token must not be called when scopes are insufficient")
		}
	}
}

func TestGHCLIProviderTokenScopeImpliedByParent(t *testing.T) {
	out := `github.com
  ✓ Logged in to github.com account GonzaloAlvarez (keyring)
  - Active account: true
  - Token scopes: 'admin'
`
	sh := &MockShell{
		RunOutputs: map[string]MockRun{
			"gh auth status": {Stdout: []byte(out)},
			"gh auth token":  {Stdout: []byte(fakeGHToken + "\n")},
		},
	}
	p := &GHCLIProvider{Shell: sh}
	tok, err := p.Token(context.Background(), []string{"admin:public_key"})
	if err != nil {
		t.Fatalf("expected token, got err %v", err)
	}
	if tok != fakeGHToken {
		t.Fatalf("token mismatch")
	}
}

func TestGHCLIProviderNeverLeaksTokenInErrors(t *testing.T) {
	cases := []struct {
		name string
		sh   *MockShell
	}{
		{
			name: "auth status fails with token in output",
			sh: &MockShell{
				RunOutputs: map[string]MockRun{
					"gh auth status": {
						Stdout: []byte("garbage with " + fakeGHToken + " in it"),
						Err:    &exec.ExitError{},
					},
				},
			},
		},
		{
			name: "auth token fails with token in stderr",
			sh: &MockShell{
				RunOutputs: map[string]MockRun{
					"gh auth status": {Stdout: []byte(sampleAuthStatusOK)},
					"gh auth token": {
						Stdout: []byte(fakeGHToken),
						Stderr: []byte("oops " + fakeGHToken),
						Err:    &exec.ExitError{},
					},
				},
			},
		},
		{
			name: "insufficient scopes with weird token-shaped scope label",
			sh: &MockShell{
				RunOutputs: map[string]MockRun{
					"gh auth status": {Stdout: []byte(sampleAuthStatusOnlyRepo)},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &GHCLIProvider{Shell: tc.sh}
			tok, err := p.Token(context.Background(), []string{"repo", "admin:public_key"})
			if tok != "" {
				if bytes.Contains([]byte(tok), []byte(fakeGHToken)) && err != nil {
					t.Fatalf("token returned in error path")
				}
			}
			if err != nil {
				if bytes.Contains([]byte(err.Error()), []byte(fakeGHToken)) {
					t.Fatalf("error message leaked token: %v", err)
				}
			}
		})
	}
}

func TestGHCLIProviderTokenIsTrimmed(t *testing.T) {
	sh := &MockShell{
		RunOutputs: map[string]MockRun{
			"gh auth status": {Stdout: []byte(sampleAuthStatusOK)},
			"gh auth token":  {Stdout: []byte("  " + fakeGHToken + "  \r\n\n")},
		},
	}
	p := &GHCLIProvider{Shell: sh}
	tok, err := p.Token(context.Background(), []string{"repo"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != fakeGHToken {
		t.Fatalf("token not trimmed; got %q", tok)
	}
}

func TestParseAuthStatusActiveAccountSelection(t *testing.T) {
	out := `github.com
  ✓ Logged in to github.com account first (keyring)
  - Active account: false
  - Token scopes: 'repo'

  ✓ Logged in to github.com account second (keyring)
  - Active account: true
  - Token scopes: 'repo', 'admin:public_key'
`
	loggedIn, scopes, err := parseAuthStatus([]byte(out))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !loggedIn {
		t.Fatalf("expected loggedIn=true")
	}
	want := []string{"repo", "admin:public_key"}
	sort.Strings(want)
	got := append([]string{}, scopes...)
	sort.Strings(got)
	if !equalStrings(got, want) {
		t.Fatalf("scopes = %v, want %v", got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
