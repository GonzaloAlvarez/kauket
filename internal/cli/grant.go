package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/manifest"
	"github.com/spf13/cobra"
)

func NewGrant(a *app.App) *cobra.Command {
	var key string
	var asOwner bool
	var yes bool
	cmd := &cobra.Command{
		Use:   "grant <identity-id> <path>",
		Short: "Grant an identity read access to a namespace or single key",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGrant(cmd.Context(), a, args[0], args[1], key, asOwner, yes)
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "grant a single key inside the namespace")
	cmd.Flags().BoolVar(&asOwner, "owner", false, "grant ownership of the namespace instead of read access")
	cmd.Flags().BoolVar(&yes, "yes", false, "noninteractive")
	return cmd
}

func runGrant(ctx context.Context, a *app.App, identityID, pathArg, key string, asOwner, yes bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if asOwner && key != "" {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: --owner applies to namespaces, not single keys")}
	}
	home, err := requireRoleHome(a, config.RoleAdmin, "kauket grant")
	if err != nil {
		return err
	}
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if asOwner && strings.HasPrefix(identityID, "h_") && !yes {
		ok, err := a.UI.Confirm(fmt.Sprintf("%s is a machine identity; an owner key on an always-on machine is a large blast radius. Grant ownership anyway?", identityID))
		if err != nil {
			return &ExitError{Code: ExitUsage, Err: err}
		}
		if !ok {
			return nil
		}
	}
	subtree := key == "" && strings.HasSuffix(strings.TrimSpace(pathArg), "/")
	path := splitNodePath(pathArg)
	var grantedRecord manifest.IdentityRecord
	post := func(repoDir, signKeyPath string, vctx *v2Context) error {
		if !asOwner || len(path) != 0 {
			return nil
		}
		return appendStoreAnchor(repoDir, signKeyPath, grantedRecord)
	}
	plan, err := runV2MutationWithPost(ctx, a, home, cfg, func(repoDir string) (manifest.Intent, error) {
		rec, err := loadRepoIdentity(repoDir, identityID)
		if err != nil {
			return manifest.Intent{}, &ExitError{Code: ExitUsage, Err: err}
		}
		grantedRecord = rec
		return manifest.Intent{Op: manifest.OpGrant, Path: path, Key: key, Identity: rec, AsOwner: asOwner, Subtree: subtree}, nil
	}, post)
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
	if asOwner {
		a.UI.Println(fmt.Sprintf("granted %s ownership of %s (%d objects updated)", identityID, target, len(plan.Written)))
		return nil
	}
	a.UI.Println(fmt.Sprintf("granted %s access to %s (%d objects updated)", identityID, target, len(plan.Written)))
	return nil
}
