package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	"github.com/gonzaloalvarez/kauket/internal/manifest"
	"github.com/spf13/cobra"
)

func NewReseal(a *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reseal",
		Short: "Re-sign the store to schema 3, activating rollback and child-name attestation protections",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReseal(cmd.Context(), a)
		},
	}
	return cmd
}

func ownsBody(body manifest.ManifestBody, signPub string) bool {
	for _, o := range body.Owners {
		if o.SignPubkey == signPub {
			return true
		}
	}
	return false
}

func runReseal(ctx context.Context, a *app.App) error {
	if ctx == nil {
		ctx = context.Background()
	}
	home, err := requireRoleHome(a, config.RoleAdmin, "kauket reseal")
	if err != nil {
		return err
	}
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if cfg.V2 == nil || cfg.V2.SignKeyPath == "" {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: this home has no v2 signing identity")}
	}
	now := a.Now
	if now == nil {
		now = time.Now
	}
	remoteURL := cfg.Repo.RemoteHTTPS
	transport, err := buildAdminSyncTransport(ctx, a, remoteURL, cfg.Repo.Owner)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	newStore := a.NewStore
	if newStore == nil {
		newStore = gitstore.OpenOrClone
	}
	store, err := newStore(ctx, gitstore.Config{
		RepoPath: config.RepoDir(home),
		URL:      remoteURL,
		LockPath: config.LockPath(home),
		Now:      now,
	}, transport)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	defer store.Close()
	if err := store.Sync(ctx); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}

	repoDir := config.RepoDir(home)
	signKeyPath := cfg.V2.SignKeyPath
	if !filepath.IsAbs(signKeyPath) {
		signKeyPath = filepath.Join(home, signKeyPath)
	}
	signerPub, err := ensureSignKey(signKeyPath)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}
	signer := bundle.Ed25519FileSigner{Path: signKeyPath}

	vctx, err := loadV2Context(home, cfg.Admin.IdentityPath, cfg.V2)
	if err != nil {
		return translateV2ReadError(err)
	}
	if vctx.root.Sealed() {
		a.UI.Println("store is already sealed (schema 3); nothing to do")
		return nil
	}
	dir := objectsDir(repoDir)
	nodes, err := manifest.LoadReadableTree(dir, vctx.root, vctx.pins, vctx.identity, bundle.Ed25519Verifier{})
	if err != nil {
		return translateV2ReadError(err)
	}

	resealed := 0
	skipped := 0
	for id, f := range nodes {
		if !ownsBody(f.Body, signerPub) {
			skipped++
			continue
		}
		body := f.Body
		if body.Schema == manifest.SchemaSealed {
			continue
		}
		body.Schema = manifest.SchemaSealed
		for i, c := range body.Children {
			if childFile, ok := nodes[c.NodeID]; ok {
				body.Children[i].Name = childFile.Body.Name
			}
		}
		body.Version++
		body.UpdatedAt = now().UTC().Format(time.RFC3339)
		signed, err := manifest.SignBody(body, signer)
		if err != nil {
			return &ExitError{Code: ExitCrypto, Err: err}
		}
		ct, _, err := manifest.EncodeManifest(manifest.ManifestFile{Body: signed, Recipients: f.Recipients}, agebox.X25519RecipientProvider{Strings: f.Recipients})
		if err != nil {
			return &ExitError{Code: ExitCrypto, Err: err}
		}
		if err := writeRepoFile(manifest.ObjectPath(dir, id), ct); err != nil {
			return &ExitError{Code: ExitSync, Err: err}
		}
		if vctx.pins != nil && signed.Version > vctx.pins.NodeVersions[id] {
			vctx.pins.NodeVersions[id] = signed.Version
		}
		resealed++
	}

	if err := rewriteStoreRoot(repoDir, signKeyPath, func(root *manifest.StoreRoot) error {
		root.Schema = manifest.SchemaSealed
		return nil
	}); err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}
	vctx.pins.StoreVersion++

	author := gitstore.Author{Name: cfg.CommitAuthor.Name, Email: cfg.CommitAuthor.Email}
	if err := store.CommitAndPush(ctx, "kauket: reseal store to schema 3", author); err != nil {
		if errors.Is(err, gitstore.ErrNonFastForward) {
			return &ExitError{Code: ExitSync, Err: errors.New("kauket: push rejected as non-fast-forward; re-run kauket reseal")}
		}
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: commit and push: %w", err)}
	}
	if err := vctx.savePins(); err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}

	a.UI.Println(fmt.Sprintf("resealed %d node(s) to schema 3", resealed))
	if skipped > 0 {
		a.UI.Println(fmt.Sprintf("%d node(s) not owned by this identity were left for their owners to reseal", skipped))
	}
	a.UI.Println("all clients must upgrade to this kauket version; older clients will reject the sealed store")
	return nil
}
