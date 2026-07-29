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

func NewRevoke(a *app.App) *cobra.Command {
	var key string
	cmd := &cobra.Command{
		Use:   "revoke <identity-id> <path>",
		Short: "Revoke an identity's access to a namespace or single key",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRevoke(cmd.Context(), a, args[0], args[1], key)
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "revoke a single key inside the namespace")
	return cmd
}

func runRevoke(ctx context.Context, a *app.App, identityID, pathArg, key string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	home, err := requireRoleHome(a, config.RoleAdmin, "kauket revoke")
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
		return manifest.Intent{Op: manifest.OpRevoke, Path: path, Key: key, Identity: rec}, nil
	})
	if err != nil {
		return err
	}
	target := pathArg
	if key != "" {
		target = pathArg + "/" + key
	}
	if plan.NoOp {
		a.UI.Println(fmt.Sprintf("%s has no access to %s", identityID, target))
		return nil
	}
	a.UI.Println(fmt.Sprintf("revoked %s from %s (%d objects re-encrypted)", identityID, target, len(plan.Written)))
	if len(plan.Rotation) > 0 {
		a.UI.Println("git history still contains ciphertexts the revoked identity can decrypt")
		a.UI.Println(fmt.Sprintf("if this identity is compromised, rotate these secrets: %s", strings.Join(plan.Rotation, ", ")))
	}
	if len(plan.Residue) > 0 {
		a.UI.Println(fmt.Sprintf("note: %d ancestor manifests keep a wider envelope until their owners rewrite them (metadata only, no content)", len(plan.Residue)))
	}
	return nil
}
