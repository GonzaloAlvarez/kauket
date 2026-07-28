package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/manifest"
	"github.com/spf13/cobra"
)

func NewVerify(a *app.App) *cobra.Command {
	var noSync bool
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Audit the v2 store: signature chain, hashes, version pins",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(cmd.Context(), a, noSync)
		},
	}
	cmd.Flags().BoolVar(&noSync, "no-sync", false, "do not sync first")
	return cmd
}

func resolveV2ReadIdentity(a *app.App) (home, identityPath string, v2 *config.V2Local, role config.Role, err error) {
	clientHome, clientExists, err := resolveRoleHome(a, config.RoleClient)
	if err != nil {
		return "", "", nil, "", err
	}
	if clientExists {
		cfg, err := config.LoadClient(clientHome)
		if err != nil {
			return "", "", nil, "", err
		}
		return clientHome, cfg.Host.IdentityPath, cfg.V2, config.RoleClient, nil
	}
	adminHome, adminExists, err := resolveRoleHome(a, config.RoleAdmin)
	if err != nil {
		return "", "", nil, "", err
	}
	if adminExists {
		cfg, err := config.LoadAdmin(adminHome)
		if err != nil {
			return "", "", nil, "", err
		}
		return adminHome, cfg.Admin.IdentityPath, cfg.V2, config.RoleAdmin, nil
	}
	return "", "", nil, "", errors.New("kauket: no kauket store configured here; run 'kauket init' or 'kauket enroll' first")
}

func runVerify(ctx context.Context, a *app.App, noSync bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	home, identityPath, v2, role, err := resolveV2ReadIdentity(a)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if !noSync {
		if role == config.RoleAdmin {
			err = syncAdmin(ctx, a, home)
		} else {
			err = syncClient(ctx, a, home)
		}
		if err != nil {
			return err
		}
	}
	if !isV2Store(config.RepoDir(home)) {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: verify requires a v2 store; run 'kauket migrate-store' first")}
	}

	vctx, err := loadV2Context(home, identityPath, v2)
	if err != nil {
		return translateV2ReadError(err)
	}
	nodes, entries, err := verifyReadableStore(vctx)
	if err != nil {
		return translateV2ReadError(err)
	}
	if err := vctx.savePins(); err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	a.UI.Println(fmt.Sprintf("verified %d nodes, %d entries", nodes, entries))
	return nil
}

func verifyReadableStore(vctx *v2Context) (int, int, error) {
	dir := objectsDir(vctx.repoDir)
	nodes, err := manifest.LoadReadableTree(dir, vctx.root, vctx.pins, vctx.identity, bundle.Ed25519Verifier{})
	if err != nil {
		return 0, 0, err
	}
	nodeIDs := make([]string, 0, len(nodes))
	for id := range nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)
	entryCount := 0
	for _, id := range nodeIDs {
		body := nodes[id].Body
		if body.IndexObjectID == "" {
			continue
		}
		ix, err := manifest.LoadIndex(dir, body, vctx.identity)
		if err != nil {
			if isNoIdentityMatch(err) {
				continue
			}
			return 0, 0, err
		}
		names := make([]string, 0, len(ix.Entries))
		for name := range ix.Entries {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			obj, err := manifest.LoadObject(dir, ix.Entries[name], vctx.identity)
			if err != nil {
				if isNoIdentityMatch(err) {
					continue
				}
				return 0, 0, err
			}
			content, err := base64.StdEncoding.DecodeString(obj.ContentBase64)
			if err != nil {
				return 0, 0, fmt.Errorf("kauket: decode content of %s: %w", name, err)
			}
			sum := sha256.Sum256(content)
			if hex.EncodeToString(sum[:]) != obj.SHA256 {
				return 0, 0, fmt.Errorf("%w: content of %s", manifest.ErrHashMismatch, name)
			}
			entryCount++
		}
	}
	return len(nodes), entryCount, nil
}
