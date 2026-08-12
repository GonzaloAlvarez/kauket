package cli

import (
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/spf13/cobra"
)

func NewStatus(a *app.App) *cobra.Command {
	var roleFlag string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Print the local kauket status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(a, roleFlag)
		},
	}
	cmd.Flags().StringVar(&roleFlag, "role", "", "limit to one role (admin|client)")
	return cmd
}

func runStatus(a *app.App, roleFlag string) error {
	targets, err := resolveTargetRoles(a, roleFlag)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		a.UI.Println("role: uninitialized")
		return nil
	}
	for i, t := range targets {
		if i > 0 {
			a.UI.Println("")
		}
		if t.role == config.RoleAdmin {
			err = statusAdmin(a, t.home)
		} else {
			err = statusClient(a, t.home)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func statusAdmin(a *app.App, home string) error {
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if err := requireV2StoreDir(config.RepoDir(home)); err != nil {
		return err
	}
	return statusV2(a, home, config.RoleAdmin, cfg.Admin.IdentityPath, cfg.V2)
}

func statusClient(a *app.App, home string) error {
	cfg, err := config.LoadClient(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if err := requireV2StoreDir(config.RepoDir(home)); err != nil {
		return err
	}
	return statusV2(a, home, config.RoleClient, cfg.Host.IdentityPath, cfg.V2)
}
