package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	"github.com/gonzaloalvarez/kauket/internal/manifest"
	"github.com/spf13/cobra"
)

type rescueFlags struct {
	recoveryIdentity string
	recoverySignKey  string
	newOwner         string
}

func NewRescue(a *app.App) *cobra.Command {
	f := &rescueFlags{}
	cmd := &cobra.Command{
		Use:   "rescue <path>",
		Short: "Use the recovery keys to appoint a new owner for an orphaned namespace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRescue(cmd.Context(), a, f, args[0])
		},
	}
	cmd.Flags().StringVar(&f.recoveryIdentity, "recovery-identity", "", "path to the recovery age identity file (required)")
	cmd.Flags().StringVar(&f.recoverySignKey, "recovery-sign-key", "", "path to the recovery signing key (required)")
	cmd.Flags().StringVar(&f.newOwner, "new-owner", "", "identity id to appoint as the node's owner (required)")
	return cmd
}

func runRescue(ctx context.Context, a *app.App, f *rescueFlags, pathArg string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if f.recoveryIdentity == "" || f.recoverySignKey == "" || f.newOwner == "" {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: rescue requires --recovery-identity, --recovery-sign-key, and --new-owner")}
	}
	home, err := requireRoleHome(a, config.RoleAdmin, "kauket rescue")
	if err != nil {
		return err
	}
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
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
	now := a.Now
	if now == nil {
		now = time.Now
	}
	store, err := newStore(ctx, gitstore.Config{
		RepoPath: config.RepoDir(home), URL: remoteURL, LockPath: config.LockPath(home), Now: now,
	}, transport)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	defer store.Close()
	if err := store.Sync(ctx); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	repoDir := config.RepoDir(home)
	if !isV2Store(repoDir) {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: rescue requires a v2 store")}
	}

	doc, sig, root, err := readStoreRootSelfVerified(repoDir)
	if err != nil {
		return translateV2ReadError(err)
	}
	_ = doc
	_ = sig
	recoveryIP := agebox.FileIdentityProvider{Path: f.recoveryIdentity}
	recoverySignPub, err := ensureSignKey(f.recoverySignKey)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}
	anchored := false
	for _, r := range root.Recovery {
		if r.SignPubkey == recoverySignPub {
			anchored = true
		}
	}
	if !anchored {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: the provided recovery signing key is not a recovery anchor of this store")}
	}

	rec, err := loadRepoIdentity(repoDir, f.newOwner)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if rec.SSHEd25519Pubkey == "" {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: identity %s has no signing key and cannot be an owner", f.newOwner)}
	}

	segments := splitNodePath(pathArg)
	engine := &manifest.Engine{
		ObjectsDir: objectsDir(repoDir),
		Root:       *root,
		Pins:       nil,
		Identity:   recoveryIP,
		Signer:     bundle.Ed25519FileSigner{Path: f.recoverySignKey},
		SignerPub:  recoverySignPub,
		ActorID:    "recovery",
		AsRecovery: true,
		Now:        now,
	}
	plan, err := engine.Apply(manifest.Intent{Op: manifest.OpGrant, Path: segments, Identity: rec, AsOwner: true})
	if err != nil {
		return translateV2ReadError(err)
	}
	if len(segments) == 0 {
		signKeyPath := f.recoverySignKey
		if err := appendStoreAnchor(repoDir, signKeyPath, rec); err != nil {
			return &ExitError{Code: ExitSync, Err: err}
		}
	}

	author := gitstore.Author{Name: cfg.CommitAuthor.Name, Email: cfg.CommitAuthor.Email}
	if err := store.CommitAndPush(ctx, "kauket: rescue node", author); err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: commit and push: %w", err)}
	}
	if plan.NoOp {
		a.UI.Println(fmt.Sprintf("%s is already an owner of %s", f.newOwner, pathArg))
		return nil
	}
	a.UI.Println(fmt.Sprintf("rescued %s: appointed %s as owner (%d objects updated)", pathArg, f.newOwner, len(plan.Written)))
	return nil
}

func readStoreRootSelfVerified(repoDir string) ([]byte, []byte, *manifest.StoreRoot, error) {
	doc, err := os.ReadFile(storeRootPath(repoDir))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("kauket: read store.json: %w", err)
	}
	sig, err := os.ReadFile(storeRootSigPath(repoDir))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("kauket: read store.json.sig: %w", err)
	}
	var raw manifest.StoreRoot
	if err := json.Unmarshal(doc, &raw); err != nil {
		return nil, nil, nil, fmt.Errorf("kauket: parse store.json: %w", err)
	}
	selfKeys := make([]string, 0, len(raw.TrustAnchors)+len(raw.Recovery))
	for _, t := range raw.TrustAnchors {
		selfKeys = append(selfKeys, t.SignPubkey)
	}
	for _, r := range raw.Recovery {
		selfKeys = append(selfKeys, r.SignPubkey)
	}
	root, err := manifest.VerifyStoreRoot(doc, sig, selfKeys, bundle.Ed25519Verifier{})
	if err != nil {
		return nil, nil, nil, err
	}
	return doc, sig, &root, nil
}
