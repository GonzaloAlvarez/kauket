package githubauth

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"strings"
)

type GHCLIProvider struct {
	Shell Shell
}

func (p *GHCLIProvider) shell() Shell {
	if p.Shell == nil {
		return SystemShell{}
	}
	return p.Shell
}

func (p *GHCLIProvider) Token(ctx context.Context, scopes []string) (string, error) {
	sh := p.shell()
	if _, err := sh.LookPath("gh"); err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
			return "", ErrGHNotInstalled
		}
		return "", ErrGHNotInstalled
	}

	stdout, stderr, runErr := sh.Run(ctx, "gh", "auth", "status")
	combined := append(append([]byte{}, stdout...), stderr...)
	if runErr != nil {
		return "", ErrGHNotAuthenticated
	}

	loggedIn, presentScopes, parseErr := parseAuthStatus(combined)
	if parseErr != nil {
		return "", fmt.Errorf("%w: failed to parse gh auth status output", ErrGHNotAuthenticated)
	}
	if !loggedIn {
		return "", ErrGHNotAuthenticated
	}

	missing := missingScopes(presentScopes, scopes)
	if len(missing) > 0 {
		return "", &InsufficientScopesError{Missing: missing}
	}

	tokenOut, _, tokenRunErr := sh.Run(ctx, "gh", "auth", "token")
	if tokenRunErr != nil {
		return "", fmt.Errorf("kauket: gh auth token failed: %w", tokenRunErr)
	}
	tok := strings.TrimSpace(string(tokenOut))
	if tok == "" {
		return "", errors.New("kauket: gh auth token returned empty output")
	}
	return tok, nil
}

func parseAuthStatus(out []byte) (loggedIn bool, scopes []string, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var inGitHubHost bool
	var inActiveAccount bool
	var currentAccountIsActive bool
	var currentAccountScopes []string
	var activeScopes []string
	activeFound := false

	flushAccount := func() {
		if currentAccountIsActive {
			activeScopes = currentAccountScopes
			activeFound = true
		}
		currentAccountIsActive = false
		currentAccountScopes = nil
	}

	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}

		if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") {
			flushAccount()
			inGitHubHost = strings.EqualFold(trimmed, "github.com")
			inActiveAccount = false
			continue
		}
		if !inGitHubHost {
			continue
		}

		if strings.Contains(trimmed, "Logged in to github.com") {
			flushAccount()
			loggedIn = true
			inActiveAccount = true
			continue
		}
		if !inActiveAccount {
			continue
		}

		if v, ok := matchKey(trimmed, "Active account"); ok {
			currentAccountIsActive = strings.EqualFold(strings.TrimSpace(v), "true")
			continue
		}
		if v, ok := matchKey(trimmed, "Token scopes"); ok {
			currentAccountScopes = parseScopes(v)
			continue
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return false, nil, scanErr
	}
	flushAccount()

	if !loggedIn {
		return false, nil, nil
	}
	if activeFound {
		return true, activeScopes, nil
	}
	return true, nil, nil
}

func matchKey(line, key string) (string, bool) {
	stripped := strings.TrimLeft(line, "-* \t")
	prefix := key + ":"
	if !strings.HasPrefix(stripped, prefix) {
		return "", false
	}
	return strings.TrimSpace(stripped[len(prefix):]), true
}

func parseScopes(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		s = strings.Trim(s, "'\"")
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func missingScopes(present, requested []string) []string {
	have := make(map[string]struct{}, len(present))
	for _, s := range present {
		have[s] = struct{}{}
	}
	var missing []string
	for _, r := range requested {
		if r == "" {
			continue
		}
		if _, ok := have[r]; ok {
			continue
		}
		if implied(have, r) {
			continue
		}
		missing = append(missing, r)
	}
	return missing
}

func implied(have map[string]struct{}, scope string) bool {
	if idx := strings.Index(scope, ":"); idx > 0 {
		parent := scope[:idx]
		if _, ok := have[parent]; ok {
			return true
		}
	}
	return false
}
