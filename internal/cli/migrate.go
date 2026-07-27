package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gofrs/flock"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/spf13/cobra"
)

func NewMigrate(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Move a legacy root-layout config into its role subdirectory",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMigrate(a)
		},
	}
}

func runMigrate(a *app.App) error {
	base, err := resolveBaseHome(a)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	role, err := config.PeekRole(base)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if role == config.RoleUninitialized {
		a.UI.Println("nothing to migrate")
		return nil
	}
	target := config.RoleHome(base, role)
	if _, err := os.Stat(config.ConfigPath(target)); err == nil {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: %s already exists; refusing to overwrite it", config.ConfigPath(target))}
	} else if !errors.Is(err, os.ErrNotExist) {
		return &ExitError{Code: ExitUsage, Err: err}
	}

	fl := flock.New(config.LockPath(base))
	locked, err := fl.TryLock()
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: lock: %w", err)}
	}
	if !locked {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: another kauket process holds the lock; try again")}
	}
	defer func() { _ = fl.Unlock() }()

	if err := os.MkdirAll(target, 0o700); err != nil {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: create role home: %w", err)}
	}
	for _, name := range []string{"identities", "git", "state", "repo", "config.json"} {
		src := filepath.Join(base, name)
		if _, err := os.Stat(src); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return &ExitError{Code: ExitUsage, Err: err}
		}
		if err := os.Rename(src, filepath.Join(target, name)); err != nil {
			return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: move %s: %w", name, err)}
		}
	}
	if err := fl.Unlock(); err != nil {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: unlock: %w", err)}
	}
	_ = os.Remove(config.LockPath(base))
	a.UI.Println(fmt.Sprintf("migrated %s role to %s", role, target))
	return nil
}
