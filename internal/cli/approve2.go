package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	"github.com/gonzaloalvarez/kauket/internal/manifest"
	"github.com/gonzaloalvarez/kauket/internal/model"
)

func runApproveV2(ctx context.Context, a *app.App, home string, cfg *config.Admin, f *approveFlags, store *gitstore.Store, useGitHub bool, token string, now func() time.Time) error {
	if cfg.V2 == nil || cfg.V2.SignKeyPath == "" {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: this home has no v2 signing identity")}
	}
	vctx, err := loadV2Context(home, cfg.Admin.IdentityPath, cfg.V2)
	if err != nil {
		return translateV2ReadError(err)
	}

	a.UI.Println("fetching pending requests")
	refs, err := store.FetchRequestRefs(ctx)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].RequestID < refs[j].RequestID })

	type v2Request struct {
		req    model.Request
		branch string
	}
	var valid []v2Request
	for _, ref := range refs {
		req, decErr := bundle.DecodeRequest(ref.Content, vctx.identity, bundle.Ed25519Verifier{})
		if decErr != nil {
			if errors.Is(decErr, bundle.ErrInvalidSignature) || errors.Is(decErr, bundle.ErrUnsignedRequest) {
				a.UI.Errorf("request %s: invalid signature; skipping", ref.Branch)
				continue
			}
			a.UI.Errorf("request %s: failed to decrypt; skipping", ref.Branch)
			continue
		}
		if req.StoreID != vctx.root.StoreID {
			a.UI.Errorf("request %s: store_id mismatch; skipping", ref.Branch)
			continue
		}
		if len(req.Requested.Paths) == 0 {
			a.UI.Errorf("request %s: no requested paths (v1-style request against a v2 store); skipping", ref.Branch)
			continue
		}
		valid = append(valid, v2Request{req: req, branch: ref.Branch})
	}
	if len(valid) == 0 {
		a.UI.Println("nothing to approve")
		return nil
	}

	a.UI.Println("")
	a.UI.Println("Pending requests:")
	a.UI.Println("")
	for i, v := range valid {
		kind := v.req.Host.Kind
		if kind == "" {
			kind = "machine"
		}
		a.UI.Println(fmt.Sprintf("%d. request %s (%s) %s %s",
			i+1, v.req.Host.DisplayName, kind, datePart(v.req.CreatedAt), strings.Join(v.req.Requested.Paths, ",")))
	}

	var selected []int
	if f.all || f.yes {
		for i := range valid {
			selected = append(selected, i)
		}
	} else {
		for i := range valid {
			ok, err := a.UI.Confirm(fmt.Sprintf("approve request %d?", i+1))
			if err != nil {
				return &ExitError{Code: ExitUsage, Err: err}
			}
			if ok {
				selected = append(selected, i)
			}
		}
	}
	if len(selected) == 0 {
		return nil
	}

	signKeyPath := cfg.V2.SignKeyPath
	if !filepath.IsAbs(signKeyPath) {
		signKeyPath = filepath.Join(home, signKeyPath)
	}
	signerPub, err := ensureSignKey(signKeyPath)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}
	repoDir := config.RepoDir(home)
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

	approvedBranches := []string{}
	for _, idx := range selected {
		v := valid[idx]
		if f.dryRun {
			a.UI.Println(fmt.Sprintf("request %d approved (dry-run)", idx+1))
			continue
		}
		if err := approveOneV2(ctx, a, engine, repoDir, vctx, v.req, cfg, useGitHub, token, now); err != nil {
			a.UI.Errorf("request %d: %v", idx+1, err)
			continue
		}
		approvedBranches = append(approvedBranches, v.req.RequestID)
		a.UI.Println(fmt.Sprintf("request %d approved", idx+1))
	}
	if len(approvedBranches) == 0 {
		return nil
	}

	author := gitstore.Author{Name: cfg.CommitAuthor.Name, Email: cfg.CommitAuthor.Email}
	if err := store.CommitAndPush(ctx, "kauket: approve request", author); err != nil {
		if errors.Is(err, gitstore.ErrNonFastForward) {
			return &ExitError{Code: ExitSync, Err: errors.New("kauket: push rejected as non-fast-forward; re-run kauket approve")}
		}
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: commit and push: %w", err)}
	}
	if err := vctx.savePins(); err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	for _, requestID := range approvedBranches {
		if err := store.DeleteRequestBranch(ctx, requestID); err != nil {
			a.UI.Errorf("request %s: approved but failed to delete request branch: %v", requestID, err)
		}
	}
	return nil
}

func approveOneV2(ctx context.Context, a *app.App, engine *manifest.Engine, repoDir string, vctx *v2Context, req model.Request, cfg *config.Admin, useGitHub bool, token string, now func() time.Time) error {
	rec, err := loadRepoIdentity(repoDir, req.Host.ID)
	known := err == nil
	if !known {
		rec = manifest.IdentityRecord{
			Schema:           manifest.Schema,
			ID:               req.Host.ID,
			AgeRecipient:     req.Host.AgeRecipient,
			SSHEd25519Pubkey: req.Host.GitDeployPublicKey,
			CreatedAt:        now().UTC().Format(time.RFC3339),
		}
		if req.Host.Kind != "user" && useGitHub {
			manager := &gitstore.DeployKeyManager{
				Owner: cfg.Repo.Owner, Repo: cfg.Repo.Name, Token: token, HTTPClient: a.HTTPClient,
			}
			if _, err := manager.Add(ctx, req.Host.ID, req.Host.GitDeployPublicKey); err != nil {
				return fmt.Errorf("deploy key add failed: %w", err)
			}
		}
		if err := writeIdentityRecord(repoDir, rec); err != nil {
			return err
		}
	} else if rec.AgeRecipient != req.Host.AgeRecipient {
		return fmt.Errorf("identity %s already bound to a different recipient; refusing", req.Host.ID)
	}

	for _, p := range req.Requested.Paths {
		segments := splitNodePath(p)
		if len(segments) == 0 {
			continue
		}
		plan, err := engine.Apply(manifest.Intent{Op: manifest.OpGrant, Path: segments, Identity: rec})
		if err == nil {
			_ = plan
			continue
		}
		if errors.Is(err, manifest.ErrNotFound) && len(segments) > 1 {
			nodePath := segments[:len(segments)-1]
			key := segments[len(segments)-1]
			_, entryErr := engine.Apply(manifest.Intent{Op: manifest.OpGrant, Path: nodePath, Key: key, Identity: rec})
			if entryErr == nil {
				continue
			}
			if errors.Is(entryErr, manifest.ErrNotFound) {
				a.UI.Println(fmt.Sprintf("warning: requested path %s does not exist; identity enrolled without that grant", p))
				continue
			}
		}
		if errors.Is(err, manifest.ErrNotFound) {
			a.UI.Println(fmt.Sprintf("warning: requested path %s does not exist; identity enrolled without that grant", p))
			continue
		}
		if errors.Is(err, manifest.ErrNotOwner) {
			if routeErr := routeRequest(engine, repoDir, vctx, req, p, segments, now); routeErr != nil {
				return routeErr
			}
			a.UI.Println(fmt.Sprintf("routed request for %s to its owners", p))
			continue
		}
		return err
	}
	return nil
}

func routeRequest(engine *manifest.Engine, repoDir string, vctx *v2Context, req model.Request, pathStr string, segments []string, now func() time.Time) error {
	nodes, err := manifest.LoadReadableTree(objectsDir(repoDir), vctx.root, vctx.pins, vctx.identity, bundle.Ed25519Verifier{})
	if err != nil {
		return err
	}
	targetID := ""
	for id, f := range nodes {
		if f.Body.Name == segments[len(segments)-1] {
			targetID = id
		}
	}
	if targetID == "" {
		return fmt.Errorf("cannot resolve routing target for %s", pathStr)
	}
	body := nodes[targetID].Body
	recipients := make([]string, 0, len(body.Owners)+1)
	for _, o := range body.Owners {
		recipients = append(recipients, o.AgeRecipient)
	}
	for _, r := range vctx.root.Recovery {
		recipients = append(recipients, r.AgeRecipient)
	}
	rr := manifest.RoutedRequest{
		Schema:       manifest.Schema,
		Kind:         manifest.KindRoutedRequest,
		StoreID:      vctx.root.StoreID,
		RequestID:    req.RequestID,
		RoutedBy:     engine.ActorID,
		RoutedAt:     now().UTC().Format(time.RFC3339),
		TargetNodeID: targetID,
		Request:      req,
	}
	ct, err := manifest.EncodeRoutedRequest(rr, agebox.X25519RecipientProvider{Strings: recipients})
	if err != nil {
		return err
	}
	return os.WriteFile(manifest.ObjectPath(objectsDir(repoDir), model.NewRoutedRequestID()), ct, 0o600)
}
