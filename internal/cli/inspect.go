package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/manifest"
	"github.com/spf13/cobra"
)

func NewInspect(a *app.App) *cobra.Command {
	var asIdentity string
	var noSync bool
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Show which secrets an identity can read (admin/owner view)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInspectAs(cmd.Context(), a, asIdentity, noSync)
		},
	}
	cmd.Flags().StringVar(&asIdentity, "as", "", "identity id to evaluate (required)")
	cmd.Flags().BoolVar(&noSync, "no-sync", false, "do not sync first")
	return cmd
}

func runInspectAs(ctx context.Context, a *app.App, asIdentity string, noSync bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if asIdentity == "" {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: inspect requires --as <identity-id>")}
	}
	home, err := requireRoleHome(a, config.RoleAdmin, "kauket inspect")
	if err != nil {
		return err
	}
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if !noSync {
		if err := syncAdmin(ctx, a, home); err != nil {
			return err
		}
	}
	if !isV2Store(config.RepoDir(home)) {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: inspect requires a v2 store")}
	}
	vctx, err := loadV2Context(home, cfg.Admin.IdentityPath, cfg.V2)
	if err != nil {
		return translateV2ReadError(err)
	}
	dir := objectsDir(vctx.repoDir)
	nodes, err := manifest.LoadReadableTree(dir, vctx.root, vctx.pins, vctx.identity, bundle.Ed25519Verifier{})
	if err != nil {
		return translateV2ReadError(err)
	}
	if err := vctx.savePins(); err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}

	pathOf := nodePathFunc(nodes)
	var readable []string
	for id, f := range nodes {
		if f.Body.IndexObjectID == "" {
			continue
		}
		ix, err := manifest.LoadIndex(dir, f.Body, vctx.identity)
		if err != nil {
			if isNoIdentityMatch(err) {
				continue
			}
			return translateV2ReadError(err)
		}
		nodeMember := identityIsMember(f.Body, asIdentity)
		for name, entry := range ix.Entries {
			granted := nodeMember
			if !granted {
				for _, r := range entry.Readers {
					if r.IID == asIdentity {
						granted = true
						break
					}
				}
			}
			if !granted {
				continue
			}
			prefix := pathOf(id)
			full := name
			if prefix != "" {
				full = prefix + "." + name
			}
			readable = append(readable, full)
		}
	}
	sort.Strings(readable)
	a.UI.Println(fmt.Sprintf("identity %s can read %d secrets:", asIdentity, len(readable)))
	for _, r := range readable {
		a.UI.Println("  " + r)
	}
	return nil
}

func identityIsMember(body manifest.ManifestBody, iid string) bool {
	for _, o := range body.Owners {
		if o.IID == iid {
			return true
		}
	}
	for _, r := range body.Readers {
		if r.IID == iid {
			return true
		}
	}
	return false
}

func nodePathFunc(nodes map[string]manifest.ManifestFile) func(string) string {
	cache := map[string]string{}
	var pathOf func(id string) string
	pathOf = func(id string) string {
		if p, ok := cache[id]; ok {
			return p
		}
		body := nodes[id].Body
		p := body.Name
		if body.ParentID != "" {
			parent := pathOf(body.ParentID)
			if parent != "" {
				p = parent + "." + body.Name
			}
		}
		cache[id] = p
		return p
	}
	return pathOf
}
