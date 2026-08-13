package install

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Options struct {
	Home            string
	Force           bool
	Backup          bool
	Now             func() time.Time
	AllowedRoots    []string
	AllowLooseModes bool
	DeniedAWSKeys   []string
}

var deniedTargetSuffixes = []string{
	"/.bashrc", "/.bash_profile", "/.bash_login", "/.profile",
	"/.zshrc", "/.zshenv", "/.zprofile", "/.zlogin",
	"/.ssh/authorized_keys", "/.ssh/authorized_keys2",
	"/.config/autostart", "/library/launchagents", "/library/launchdaemons",
	"/.config/systemd",
}

func checkWithinAllowedRoot(dest string, roots []string) error {
	if len(roots) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("install: user home: %w", err)
		}
		if resolved, rerr := filepath.EvalSymlinks(home); rerr == nil {
			home = resolved
		}
		roots = []string{home}
	}
	cleaned := filepath.Clean(dest)
	for _, r := range roots {
		rc := filepath.Clean(expandRoot(r))
		if cleaned == rc || strings.HasPrefix(cleaned, rc+string(os.PathSeparator)) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrDestinationOutsideRoot, dest)
}

func expandRoot(r string) string {
	if strings.HasPrefix(r, "~/") || r == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			if resolved, rerr := filepath.EvalSymlinks(home); rerr == nil {
				home = resolved
			}
			if r == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(r, "~/"))
		}
	}
	return r
}

func checkNotDeniedTarget(dest string) error {
	lower := strings.ToLower(filepath.ToSlash(dest))
	for _, suf := range deniedTargetSuffixes {
		if strings.HasSuffix(lower, suf) || strings.Contains(lower, suf+"/") {
			return fmt.Errorf("%w: %s", ErrDeniedTarget, dest)
		}
	}
	return nil
}

type ResultStatus int

const (
	StatusCreated ResultStatus = iota
	StatusReplaced
	StatusNoChange
	StatusBackedUpAndReplaced
)

type Result struct {
	Status     ResultStatus
	BackupPath string
}

func PreflightInstall(spec InstallSpec, opts Options) error {
	if containsTraversal(spec.Destination) {
		return ErrPathTraversal
	}
	expanded, err := expandPath(spec.Destination)
	if err != nil {
		return err
	}
	if containsTraversal(expanded) {
		return ErrPathTraversal
	}
	if !filepath.IsAbs(expanded) {
		return ErrRelativeDest
	}
	if err := checkWithinAllowedRoot(expanded, opts.AllowedRoots); err != nil {
		return err
	}
	if err := checkNotDeniedTarget(expanded); err != nil {
		return err
	}
	if err := ValidateSecretMode(spec.Mode, opts.AllowLooseModes); err != nil {
		return err
	}
	return ValidateDirMode(spec.DirectoryMode)
}

func InstallFile(id string, content []byte, spec InstallSpec, opts Options) (Result, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	if containsTraversal(spec.Destination) {
		return Result{}, ErrPathTraversal
	}
	expanded, err := expandPath(spec.Destination)
	if err != nil {
		return Result{}, err
	}
	if containsTraversal(expanded) {
		return Result{}, ErrPathTraversal
	}
	if !filepath.IsAbs(expanded) {
		return Result{}, ErrRelativeDest
	}
	if err := checkWithinAllowedRoot(expanded, opts.AllowedRoots); err != nil {
		return Result{}, err
	}
	if err := checkNotDeniedTarget(expanded); err != nil {
		return Result{}, err
	}
	if err := ValidateSecretMode(spec.Mode, opts.AllowLooseModes); err != nil {
		return Result{}, err
	}
	if err := ValidateDirMode(spec.DirectoryMode); err != nil {
		return Result{}, err
	}

	if err := checkNoSymlinkAncestors(expanded); err != nil {
		return Result{}, err
	}

	parent := filepath.Dir(expanded)
	if err := ensureParentDirs(parent, spec.DirectoryMode); err != nil {
		return Result{}, err
	}

	if err := checkDestNotSymlink(expanded); err != nil {
		return Result{}, err
	}

	newHash := sha256.Sum256(content)
	newHashHex := hex.EncodeToString(newHash[:])

	state, err := LoadState(opts.Home)
	if err != nil {
		return Result{}, err
	}

	existed := false
	var existingHashHex string
	if info, err := os.Lstat(expanded); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return Result{}, &SymlinkInPathError{Path: expanded}
		}
		if !info.Mode().IsRegular() {
			return Result{}, fmt.Errorf("install: destination is not a regular file: %s", expanded)
		}
		existed = true
		existingBytes, err := os.ReadFile(expanded)
		if err != nil {
			return Result{}, fmt.Errorf("install: read existing destination: %w", err)
		}
		sum := sha256.Sum256(existingBytes)
		existingHashHex = hex.EncodeToString(sum[:])
	} else if !errors.Is(err, os.ErrNotExist) {
		return Result{}, fmt.Errorf("install: stat destination: %w", err)
	}

	if existed && existingHashHex == newHashHex {
		return Result{Status: StatusNoChange}, nil
	}

	managed := false
	if existed {
		entry, ok := state.Installed[id]
		if ok && entry.ExpandedDestination == expanded && entry.SHA256 == existingHashHex {
			managed = true
		}
	}

	result := Result{Status: StatusCreated}
	if existed {
		switch {
		case managed:
			result.Status = StatusReplaced
		case opts.Backup:
			backupPath, err := makeBackup(expanded, now())
			if err != nil {
				return Result{}, err
			}
			result.Status = StatusBackedUpAndReplaced
			result.BackupPath = backupPath
		case opts.Force:
			result.Status = StatusReplaced
		default:
			return Result{}, ErrUnmanagedDestination
		}
	}

	if err := atomicWrite(expanded, content, spec.Mode); err != nil {
		return Result{}, err
	}

	state.Installed[id] = Entry{
		Destination:         spec.Destination,
		ExpandedDestination: expanded,
		SHA256:              newHashHex,
		InstalledAt:         now().UTC().Format(time.RFC3339),
	}
	if err := SaveState(opts.Home, state); err != nil {
		return Result{}, err
	}

	return result, nil
}

func expandPath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("install: empty destination")
	}
	if strings.HasPrefix(p, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("install: user home: %w", err)
		}
		if resolved, err := filepath.EvalSymlinks(home); err == nil {
			home = resolved
		}
		rest := strings.TrimPrefix(p, "~")
		if rest == "" {
			return home, nil
		}
		if rest[0] == '/' {
			return filepath.Join(home, rest), nil
		}
		return "", fmt.Errorf("install: unsupported ~ expansion in %q", p)
	}
	return p, nil
}

func containsTraversal(p string) bool {
	slashed := filepath.ToSlash(p)
	if strings.Contains(slashed, "/../") {
		return true
	}
	if strings.HasPrefix(slashed, "../") {
		return true
	}
	if strings.HasSuffix(slashed, "/..") {
		return true
	}
	if slashed == ".." {
		return true
	}
	return false
}

func ancestorsOf(p string) []string {
	cleaned := filepath.Clean(p)
	parent := filepath.Dir(cleaned)
	chain := []string{}
	for {
		chain = append(chain, parent)
		next := filepath.Dir(parent)
		if next == parent {
			break
		}
		parent = next
	}
	out := make([]string, len(chain))
	for i, v := range chain {
		out[len(chain)-1-i] = v
	}
	return out
}

func checkNoSymlinkAncestors(dest string) error {
	for _, a := range ancestorsOf(dest) {
		info, err := os.Lstat(a)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("install: lstat %s: %w", a, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return &SymlinkInPathError{Path: a}
		}
	}
	return nil
}

func checkDestNotSymlink(dest string) error {
	info, err := os.Lstat(dest)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("install: lstat destination: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return &SymlinkInPathError{Path: dest}
	}
	return nil
}

func ensureParentDirs(parent string, mode os.FileMode) error {
	missing := []string{}
	cur := parent
	for {
		info, err := os.Lstat(cur)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return &SymlinkInPathError{Path: cur}
			}
			if !info.IsDir() {
				return fmt.Errorf("%w: %s", ErrParentNotDir, cur)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("install: lstat %s: %w", cur, err)
		}
		missing = append(missing, cur)
		next := filepath.Dir(cur)
		if next == cur {
			return fmt.Errorf("install: no existing ancestor for %s", parent)
		}
		cur = next
	}
	for i := len(missing) - 1; i >= 0; i-- {
		dir := missing[i]
		if err := os.Mkdir(dir, mode); err != nil {
			return fmt.Errorf("install: mkdir %s: %w", dir, err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			return fmt.Errorf("install: chmod %s: %w", dir, err)
		}
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("install: stat %s: %w", dir, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("%w: %s", ErrParentNotDir, dir)
		}
	}
	return nil
}

func atomicWrite(dest string, content []byte, mode os.FileMode) error {
	parent := filepath.Dir(dest)
	tmp, err := os.CreateTemp(parent, ".kauket-")
	if err != nil {
		return fmt.Errorf("install: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleaned := false
	defer func() {
		if !cleaned {
			os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return fmt.Errorf("install: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("install: sync temp: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("install: chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("install: close temp: %w", err)
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		return fmt.Errorf("install: rename: %w", err)
	}
	cleaned = true

	if dir, err := os.Open(parent); err == nil {
		_ = dir.Sync()
		dir.Close()
	}
	return nil
}

func makeBackup(dest string, ts time.Time) (string, error) {
	stamp := ts.UTC().Format("20060102T150405")
	backupPath := fmt.Sprintf("%s.kauket-bak-%s", dest, stamp)
	if err := os.Rename(dest, backupPath); err != nil {
		return "", fmt.Errorf("install: backup: %w", err)
	}
	return backupPath, nil
}
