package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/model"
	"github.com/spf13/cobra"
)

func NewList(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List secrets visible to this role",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(a)
		},
	}
}

func runList(a *app.App) error {
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
		return listAdmin(a, home)
	case config.RoleClient:
		return listClient(a, home)
	default:
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: no kauket store configured here")}
	}
}

func listAdmin(a *app.App, home string) error {
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
	ids := make([]string, 0, len(vault.Secrets))
	for id := range vault.Secrets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		secret := vault.Secrets[id]
		hosts := countHosts(vault, id, secret.Profiles)
		a.UI.Println(fmt.Sprintf("%s  profiles=%s  hosts=%d", id, strings.Join(secret.Profiles, ","), hosts))
	}
	return nil
}

func listClient(a *app.App, home string) error {
	cfg, err := config.LoadClient(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	bundlePath := filepath.Join(config.RepoDir(home), "bundles", cfg.Host.ID+".age")
	ct, err := os.ReadFile(bundlePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &ExitError{Code: ExitNotGranted, Err: errors.New("kauket: no approved bundle found for this machine\nrequest is pending or has not been approved")}
		}
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: read bundle: %w", err)}
	}
	identityPath := cfg.Host.IdentityPath
	if !filepath.IsAbs(identityPath) {
		identityPath = filepath.Join(home, identityPath)
	}
	b, err := bundle.DecodeHostBundle(ct, agebox.FileIdentityProvider{Path: identityPath})
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: decrypt bundle: %w", err)}
	}
	ids := make([]string, 0, len(b.Secrets))
	for id := range b.Secrets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		a.UI.Println(id)
	}
	return nil
}

func countHosts(v model.Vault, secretID string, profiles []string) int {
	profileSet := make(map[string]struct{}, len(profiles))
	for _, p := range profiles {
		profileSet[p] = struct{}{}
	}
	count := 0
	for _, host := range v.Hosts {
		match := false
		for _, gs := range host.GrantedSecrets {
			if gs == secretID {
				match = true
				break
			}
		}
		if !match {
			for _, gp := range host.GrantedProfiles {
				if _, ok := profileSet[gp]; ok {
					match = true
					break
				}
			}
		}
		if match {
			count++
		}
	}
	return count
}
