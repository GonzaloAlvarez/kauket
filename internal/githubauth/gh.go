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
	"time"
)

const (
	ghHost           = "github.com"
	defaultGHTimeout = 10 * time.Second
)

type GHCLIProvider struct {
	Shell   Shell
	Account string
	Timeout time.Duration
}

func (p *GHCLIProvider) shell() Shell {
	if p.Shell == nil {
		return SystemShell{}
	}
	return p.Shell
}

func (p *GHCLIProvider) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return defaultGHTimeout
}

func (p *GHCLIProvider) run(ctx context.Context, sh Shell, args ...string) ([]byte, []byte, error) {
	runCtx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	stdout, stderr, err := sh.Run(runCtx, "gh", args...)
	if err != nil && errors.Is(runCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		return stdout, stderr, fmt.Errorf("%w: %q gave no answer within %s; ensure your internet connectivity is working", ErrGHTimeout, "gh "+strings.Join(args, " "), p.timeout())
	}
	return stdout, stderr, err
}

func (p *GHCLIProvider) Token(ctx context.Context, scopes []string) (string, error) {
	sh := p.shell()
	if _, err := sh.LookPath("gh"); err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
			return "", ErrGHNotInstalled
		}
		return "", ErrGHNotInstalled
	}

	stdout, stderr, runErr := p.run(ctx, sh, "auth", "status", "--hostname", ghHost)
	if errors.Is(runErr, ErrGHTimeout) {
		return "", runErr
	}
	combined := append(append([]byte{}, stdout...), stderr...)
	if runErr != nil {
		return "", ErrGHNotAuthenticated
	}

	accounts, parseErr := parseAuthStatus(combined, ghHost)
	if parseErr != nil {
		return "", fmt.Errorf("%w: failed to parse gh auth status output", ErrGHNotAuthenticated)
	}
	account, ok := chooseAccount(accounts, p.Account)
	if !ok {
		return "", ErrGHNotAuthenticated
	}

	missing := missingScopes(account.Scopes, scopes)
	if len(missing) > 0 {
		return "", &InsufficientScopesError{Missing: missing}
	}

	tokenArgs := []string{"auth", "token", "--hostname", ghHost}
	if account.Name != "" {
		tokenArgs = append(tokenArgs, "--user", account.Name)
	}
	tokenOut, _, tokenRunErr := p.run(ctx, sh, tokenArgs...)
	if errors.Is(tokenRunErr, ErrGHTimeout) {
		return "", tokenRunErr
	}
	if tokenRunErr != nil {
		return "", fmt.Errorf("kauket: gh auth token failed: %w", tokenRunErr)
	}
	tok := strings.TrimSpace(string(tokenOut))
	if tok == "" {
		return "", errors.New("kauket: gh auth token returned empty output")
	}
	return tok, nil
}

type ghAccount struct {
	Name   string
	Active bool
	Scopes []string
}

func parseAuthStatus(out []byte, host string) ([]ghAccount, error) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var accounts []ghAccount
	var inHost bool
	var current *ghAccount

	flush := func() {
		if current != nil {
			accounts = append(accounts, *current)
		}
		current = nil
	}

	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}

		if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") {
			flush()
			inHost = strings.EqualFold(trimmed, host)
			continue
		}
		if !inHost {
			continue
		}

		if strings.Contains(trimmed, "Logged in to "+host) {
			flush()
			current = &ghAccount{Name: accountName(trimmed)}
			continue
		}
		if current == nil {
			continue
		}

		if v, ok := matchKey(trimmed, "Active account"); ok {
			current.Active = strings.EqualFold(strings.TrimSpace(v), "true")
			continue
		}
		if v, ok := matchKey(trimmed, "Token scopes"); ok {
			current.Scopes = parseScopes(v)
			continue
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return nil, scanErr
	}
	flush()
	return accounts, nil
}

func accountName(line string) string {
	const marker = " account "
	idx := strings.Index(line, marker)
	if idx < 0 {
		return ""
	}
	fields := strings.Fields(line[idx+len(marker):])
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func chooseAccount(accounts []ghAccount, preferred string) (ghAccount, bool) {
	if preferred != "" {
		for _, a := range accounts {
			if strings.EqualFold(a.Name, preferred) {
				return a, true
			}
		}
	}
	for _, a := range accounts {
		if a.Active {
			return a, true
		}
	}
	if len(accounts) > 0 {
		return accounts[0], true
	}
	return ghAccount{}, false
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
