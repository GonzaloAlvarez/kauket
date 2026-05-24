package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/install"
	"github.com/spf13/cobra"
)

func NewStatus(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Print the local kauket status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(a)
		},
	}
}

func runStatus(a *app.App) error {
	home, err := resolveHome(a)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	role, err := config.PeekRole(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	switch role {
	case config.RoleAdmin:
		return statusAdmin(a, home)
	case config.RoleClient:
		return statusClient(a, home)
	default:
		a.UI.Println("role: uninitialized")
		return nil
	}
}

func statusAdmin(a *app.App, home string) error {
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	vaultPath := filepath.Join(config.RepoDir(home), "admin", "vault.age")
	ct, err := os.ReadFile(vaultPath)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: read admin vault: %w", err)}
	}
	identityPath := cfg.Admin.IdentityPath
	if !filepath.IsAbs(identityPath) {
		identityPath = filepath.Join(home, identityPath)
	}
	vault, err := bundle.DecodeVault(ct, agebox.FileIdentityProvider{Path: identityPath})
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: decrypt admin vault: %w", err)}
	}
	pending := 0
	for _, r := range vault.Requests {
		if r.Status == "" || r.Status == "pending" {
			pending++
		}
	}
	a.UI.Println("role: admin")
	a.UI.Println(fmt.Sprintf("store: %s/%s", cfg.Repo.Owner, cfg.Repo.Name))
	a.UI.Println(fmt.Sprintf("secrets: %d", len(vault.Secrets)))
	a.UI.Println(fmt.Sprintf("hosts: %d", len(vault.Hosts)))
	a.UI.Println(fmt.Sprintf("pending_requests: %d", pending))
	return nil
}

func statusClient(a *app.App, home string) error {
	cfg, err := config.LoadClient(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	bundlePath := filepath.Join(config.RepoDir(home), "bundles", cfg.Host.ID+".age")
	bundleStatus := "absent"
	if _, err := os.Stat(bundlePath); err == nil {
		bundleStatus = "present"
	} else if !errors.Is(err, os.ErrNotExist) {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: stat bundle: %w", err)}
	}

	lastSync := ""
	state, stateErr := install.LoadState(home)
	if stateErr == nil && state != nil {
		var latest string
		for _, e := range state.Installed {
			if e.InstalledAt > latest {
				latest = e.InstalledAt
			}
		}
		lastSync = latest
	}

	a.UI.Println("role: client")
	a.UI.Println(fmt.Sprintf("store: %s/%s", cfg.Repo.Owner, cfg.Repo.Name))
	a.UI.Println(fmt.Sprintf("host_id: %s", cfg.Host.ID))
	a.UI.Println(fmt.Sprintf("bundle: %s", bundleStatus))
	a.UI.Println(fmt.Sprintf("last_sync: %s", lastSync))
	return nil
}
