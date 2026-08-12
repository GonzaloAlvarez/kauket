package cli

import (
	"errors"
	"fmt"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/spf13/cobra"
)

func NewList(a *app.App) *cobra.Command {
	var roleFlag string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secrets visible to this role",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(a, roleFlag)
		},
	}
	cmd.Flags().StringVar(&roleFlag, "role", "", "limit to one role (admin|client)")
	return cmd
}

func runList(a *app.App, roleFlag string) error {
	targets, err := resolveTargetRoles(a, roleFlag)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: no kauket store configured here")}
	}
	dual := len(targets) > 1
	for i, t := range targets {
		if dual {
			if i > 0 {
				a.UI.Println("")
			}
			a.UI.Println(fmt.Sprintf("role: %s", t.role))
		}
		if t.role == config.RoleAdmin {
			err = listAdmin(a, t.home)
		} else {
			err = listClient(a, t.home)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func listAdmin(a *app.App, home string) error {
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if err := requireV2StoreDir(config.RepoDir(home)); err != nil {
		return err
	}
	return listV2(a, home, cfg.Admin.IdentityPath, cfg.V2)
}

func listClient(a *app.App, home string) error {
	cfg, err := config.LoadClient(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if err := requireV2StoreDir(config.RepoDir(home)); err != nil {
		return err
	}
	return listV2(a, home, cfg.Host.IdentityPath, cfg.V2)
}
