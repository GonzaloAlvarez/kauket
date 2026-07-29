package cli

import (
	"context"
	"fmt"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/manifest"
	"github.com/spf13/cobra"
)

func NewGrant(a *app.App) *cobra.Command {
	var key string
	cmd := &cobra.Command{
		Use:   "grant <identity-id> <path>",
		Short: "Grant an identity read access to a namespace or single key",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGrant(cmd.Context(), a, args[0], args[1], key)
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "grant a single key inside the namespace")
	return cmd
}

func runGrant(ctx context.Context, a *app.App, identityID, pathArg, key string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	home, err := requireRoleHome(a, config.RoleAdmin, "kauket grant")
	if err != nil {
		return err
	}
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	path := splitNodePath(pathArg)
	plan, err := runV2Mutation(ctx, a, home, cfg, func(repoDir string) (manifest.Intent, error) {
		rec, err := loadRepoIdentity(repoDir, identityID)
		if err != nil {
			return manifest.Intent{}, &ExitError{Code: ExitUsage, Err: err}
		}
		return manifest.Intent{Op: manifest.OpGrant, Path: path, Key: key, Identity: rec}, nil
	})
	if err != nil {
		return err
	}
	target := pathArg
	if key != "" {
		target = pathArg + "/" + key
	}
	if plan.NoOp {
		a.UI.Println(fmt.Sprintf("%s already has access to %s", identityID, target))
		return nil
	}
	a.UI.Println(fmt.Sprintf("granted %s access to %s (%d objects updated)", identityID, target, len(plan.Written)))
	return nil
}
