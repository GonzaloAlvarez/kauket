package install

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gonzaloalvarez/kauket/internal/awsconfig"
)

type FileResult struct {
	Destination string
	Status      ResultStatus
	BackupPath  string
}

type ProfileResult struct {
	Profile string
	Files   []FileResult
}

type profileTarget struct {
	display  string
	expanded string
	label    string
	kind     awsconfig.FileKind
	incoming string
	existing []byte
	existed  bool
	mode     os.FileMode
	merge    awsconfig.MergeResult
	status   ResultStatus
	backup   bool
}

func InstallAWSProfile(id string, content []byte, opts Options) (ProfileResult, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	env, err := awsconfig.ParseEnvelope(content)
	if err != nil {
		return ProfileResult{}, fmt.Errorf("install: %w", err)
	}

	state, err := LoadState(opts.Home)
	if err != nil {
		return ProfileResult{}, err
	}
	entry, hasEntry := state.Installed[id]

	var targets []*profileTarget
	if env.Config != "" {
		targets = append(targets, &profileTarget{
			display:  displayPath(os.Getenv("AWS_CONFIG_FILE"), "~/.aws/config"),
			label:    "config",
			kind:     awsconfig.KindConfig,
			incoming: env.Config,
		})
	}
	if env.Credentials != "" {
		targets = append(targets, &profileTarget{
			display:  displayPath(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"), "~/.aws/credentials"),
			label:    "credentials",
			kind:     awsconfig.KindCredentials,
			incoming: env.Credentials,
		})
	}

	for _, t := range targets {
		if err := planProfileTarget(t); err != nil {
			return ProfileResult{}, err
		}
		if t.status != StatusNoChange && t.existed {
			if err := decideExistingTarget(t, entry, hasEntry, opts); err != nil {
				return ProfileResult{}, err
			}
		}
	}

	wrote := false
	result := ProfileResult{Profile: env.Profile}
	for _, t := range targets {
		fr := FileResult{Destination: t.display, Status: t.status}
		if t.status != StatusNoChange {
			parent := filepath.Dir(t.expanded)
			if err := ensureParentDirs(parent, 0o700); err != nil {
				return ProfileResult{}, err
			}
			if t.backup {
				backupPath, err := makeBackup(t.expanded, now())
				if err != nil {
					return ProfileResult{}, err
				}
				fr.BackupPath = backupPath
			}
			if err := atomicWrite(t.expanded, t.merge.Output, t.mode); err != nil {
				return ProfileResult{}, err
			}
			wrote = true
		}
		result.Files = append(result.Files, fr)
	}

	if wrote {
		sections := map[string]string{}
		displays := ""
		expandeds := ""
		for i, t := range targets {
			if i > 0 {
				displays += ", "
				expandeds += ", "
			}
			displays += t.display
			expandeds += t.expanded
			for _, p := range t.merge.Sections {
				sections[t.label+"|"+p.Key] = p.IncomingSHA256
			}
		}
		sum := sha256.Sum256(content)
		state.Installed[id] = Entry{
			Destination:         displays,
			ExpandedDestination: expandeds,
			SHA256:              hex.EncodeToString(sum[:]),
			InstalledAt:         now().UTC().Format(time.RFC3339),
			Sections:            sections,
		}
		if err := SaveState(opts.Home, state); err != nil {
			return ProfileResult{}, err
		}
	}
	return result, nil
}

func displayPath(override, fallback string) string {
	if override != "" {
		return override
	}
	return fallback
}

func planProfileTarget(t *profileTarget) error {
	if containsTraversal(t.display) {
		return ErrPathTraversal
	}
	expanded, err := expandPath(t.display)
	if err != nil {
		return err
	}
	if containsTraversal(expanded) {
		return ErrPathTraversal
	}
	if !filepath.IsAbs(expanded) {
		return ErrRelativeDest
	}
	if err := checkNoSymlinkAncestors(expanded); err != nil {
		return err
	}
	if err := checkDestNotSymlink(expanded); err != nil {
		return err
	}
	t.expanded = expanded
	t.mode = 0o600
	if info, err := os.Lstat(expanded); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return &SymlinkInPathError{Path: expanded}
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("install: destination is not a regular file: %s", expanded)
		}
		data, readErr := os.ReadFile(expanded)
		if readErr != nil {
			return fmt.Errorf("install: read existing destination: %w", readErr)
		}
		t.existed = true
		t.existing = data
		t.mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("install: stat destination: %w", err)
	}
	merge, err := awsconfig.Merge(t.existing, t.incoming, t.kind)
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	t.merge = merge
	switch {
	case !t.existed:
		t.status = StatusCreated
	case !merge.Changed:
		t.status = StatusNoChange
	default:
		t.status = StatusReplaced
	}
	return nil
}

func decideExistingTarget(t *profileTarget, entry Entry, hasEntry bool, opts Options) error {
	var conflict *awsconfig.SectionPlan
	for i := range t.merge.Sections {
		p := &t.merge.Sections[i]
		if !p.Existing || !p.Differs {
			continue
		}
		if !hasEntry || entry.Sections[t.label+"|"+p.Key] != p.ExistingSHA256 {
			conflict = p
			break
		}
	}
	if conflict == nil {
		return nil
	}
	switch {
	case opts.Backup:
		t.status = StatusBackedUpAndReplaced
		t.backup = true
	case opts.Force:
		t.status = StatusReplaced
	default:
		return fmt.Errorf("%w: [%s] in %s differs; use --force or --backup", ErrUnmanagedSection, conflict.Header, t.expanded)
	}
	return nil
}
