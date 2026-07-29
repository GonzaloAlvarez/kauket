package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	"github.com/gonzaloalvarez/kauket/internal/manifest"
)

const maxMutationRetries = 5

func splitNodePath(arg string) []string {
	sep := "."
	if strings.Contains(arg, "/") {
		sep = "/"
	}
	var out []string
	for _, s := range strings.Split(strings.Trim(arg, "/"), sep) {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func loadRepoIdentity(repoDir, id string) (manifest.IdentityRecord, error) {
	data, err := os.ReadFile(filepath.Join(repoIdentitiesDir(repoDir), id+".json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return manifest.IdentityRecord{}, fmt.Errorf("kauket: identity %s is not enrolled in this store", id)
		}
		return manifest.IdentityRecord{}, fmt.Errorf("kauket: read identity %s: %w", id, err)
	}
	var rec manifest.IdentityRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return manifest.IdentityRecord{}, fmt.Errorf("kauket: parse identity %s: %w", id, err)
	}
	return rec, nil
}

func runV2Mutation(ctx context.Context, a *app.App, home string, cfg *config.Admin, buildIntent func(repoDir string) (manifest.Intent, error)) (*manifest.Plan, error) {
	return runV2MutationWithPost(ctx, a, home, cfg, buildIntent, nil)
}

func runV2MutationWithPost(ctx context.Context, a *app.App, home string, cfg *config.Admin, buildIntent func(repoDir string) (manifest.Intent, error), postApply func(repoDir, signKeyPath string, vctx *v2Context) error) (*manifest.Plan, error) {
	if cfg.V2 == nil || cfg.V2.SignKeyPath == "" {
		return nil, &ExitError{Code: ExitUsage, Err: errors.New("kauket: this home has no v2 signing identity; run 'kauket migrate-store' or 'kauket init --v2' first")}
	}
	remoteURL := cfg.Repo.RemoteHTTPS
	transport, err := buildAdminSyncTransport(ctx, a, remoteURL, cfg.Repo.Owner)
	if err != nil {
		return nil, &ExitError{Code: ExitSync, Err: err}
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
		RepoPath: config.RepoDir(home),
		URL:      remoteURL,
		LockPath: config.LockPath(home),
		Now:      now,
	}, transport)
	if err != nil {
		return nil, &ExitError{Code: ExitSync, Err: err}
	}
	defer store.Close()

	signKeyPath := cfg.V2.SignKeyPath
	if !filepath.IsAbs(signKeyPath) {
		signKeyPath = filepath.Join(home, signKeyPath)
	}
	signerPub, err := ensureSignKey(signKeyPath)
	if err != nil {
		return nil, &ExitError{Code: ExitCrypto, Err: err}
	}

	for attempt := 0; attempt < maxMutationRetries; attempt++ {
		if err := store.Sync(ctx); err != nil {
			return nil, &ExitError{Code: ExitSync, Err: err}
		}
		repoDir := config.RepoDir(home)
		if !isV2Store(repoDir) {
			return nil, &ExitError{Code: ExitUsage, Err: errors.New("kauket: this operation requires a v2 store; run 'kauket migrate-store' first")}
		}
		vctx, err := loadV2Context(home, cfg.Admin.IdentityPath, cfg.V2)
		if err != nil {
			return nil, translateV2ReadError(err)
		}
		intent, err := buildIntent(repoDir)
		if err != nil {
			return nil, err
		}
		engine := &manifest.Engine{
			ObjectsDir: objectsDir(repoDir),
			Root:       vctx.root,
			Pins:       vctx.pins,
			Identity:   vctx.identity,
			Signer:     bundle.Ed25519FileSigner{Path: signKeyPath},
			SignerPub:  signerPub,
			ActorID:    cfg.V2.IdentityID,
			Now:        now,
		}
		plan, err := engine.Apply(intent)
		if err != nil {
			return nil, translateV2ReadError(err)
		}
		if plan.NoOp {
			return plan, nil
		}
		if postApply != nil {
			if err := postApply(repoDir, signKeyPath, vctx); err != nil {
				return nil, err
			}
		}
		author := gitstore.Author{Name: cfg.CommitAuthor.Name, Email: cfg.CommitAuthor.Email}
		err = store.CommitAndPush(ctx, "kauket: update objects", author)
		if err == nil {
			if err := vctx.savePins(); err != nil {
				return nil, &ExitError{Code: ExitUsage, Err: err}
			}
			return plan, nil
		}
		if errors.Is(err, gitstore.ErrNonFastForward) {
			continue
		}
		return nil, &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: commit and push: %w", err)}
	}
	return nil, &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: could not push after %d attempts; re-run the command", maxMutationRetries)}
}
