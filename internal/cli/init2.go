package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/githubauth"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	"github.com/gonzaloalvarez/kauket/internal/manifest"
	"github.com/gonzaloalvarez/kauket/internal/model"
)

func runInitV2(ctx context.Context, a *app.App, f *initFlags) error {
	if f.recoveryOut == "" {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: --v2 requires --recovery-out <dir> for the offline recovery key pair")}
	}
	home, _, err := resolveRoleHome(a, config.RoleAdmin)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: resolve home: %w", err)}
	}
	if err := config.EnsureIdentitiesDir(home); err != nil {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: create identities dir: %w", err)}
	}

	identityPath := config.AdminIdentityPath(home)
	recipient, err := ensureAdminIdentity(identityPath, f.adminIdentity)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}
	signKeyPath := filepath.Join(home, "identities", "sign.key")
	signPub, err := ensureSignKey(signKeyPath)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}
	recoveryRecipient, recoverySignPub, err := writeRecoveryPair(f.recoveryOut)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}

	remoteURL := strings.TrimSpace(f.remote)
	if remoteURL == "" {
		remoteURL = fmt.Sprintf("https://github.com/%s/%s.git", f.owner, f.repo)
	}
	useGitHub := !f.noGitHub && !strings.HasPrefix(remoteURL, "file://")
	if useGitHub && (strings.HasPrefix(remoteURL, "git@") || strings.HasPrefix(remoteURL, "ssh://")) {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: admin init does not support SSH remotes; use an HTTPS GitHub URL or pass --no-github with a local file remote")}
	}

	var transport gitstore.Transport
	var token string
	if useGitHub {
		printCode := func(verifyURL, userCode string) {
			a.UI.Println(fmt.Sprintf("open %s and enter code %s", verifyURL, userCode))
		}
		tok, _, authErr := githubauth.Select(ctx, []string{"repo", "admin:public_key"}, githubauth.SelectorOptions{
			Shell:           a.AuthShell,
			ClientID:        githubauth.ClientID,
			Account:         f.owner,
			PrintCode:       printCode,
			HTTPClient:      a.HTTPClient,
			AllowDeviceFlow: true,
		})
		if authErr != nil {
			return &ExitError{Code: ExitSync, Err: authErr}
		}
		token = tok
		transport = gitstore.HTTPSTokenTransport{Token: token}
		if err := ensureGitHubRepo(ctx, a.HTTPClient, token, f.owner, f.repo, f.private); err != nil {
			return &ExitError{Code: ExitSync, Err: err}
		}
	} else {
		transport = gitstore.FileURLTransport{}
	}

	now := a.Now
	if now == nil {
		now = time.Now
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

	if isV2Store(config.RepoDir(home)) {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: remote already holds a v2 store")}
	}

	storeID := model.NewStoreID()
	founderID := model.NewIdentityID()
	rootNodeID := model.NewNodeID()
	rootIndexID := model.NewIndexObjectID()
	createdAt := now().UTC().Format(time.RFC3339)
	recovery := []string{recoveryRecipient}

	rootBody := manifest.ManifestBody{
		Schema: manifest.Schema, Kind: manifest.KindManifest,
		StoreID: storeID, NodeID: rootNodeID, Version: 1, UpdatedAt: createdAt,
		Name: "", ParentID: "",
		Owners:        []manifest.Owner{{IID: founderID, AgeRecipient: recipient, SignPubkey: signPub}},
		IndexObjectID: rootIndexID,
	}
	rootIndex := manifest.Index{
		Schema: manifest.Schema, Kind: manifest.KindIndex,
		StoreID: storeID, NodeID: rootNodeID, Entries: map[string]manifest.IndexEntry{},
	}
	tree := manifest.Tree{rootNodeID: rootBody}

	ixRecipients, err := manifest.RecipientSet(manifest.ArtifactIndex, rootNodeID, "", tree, nil, recovery)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}
	ixCT, ixSHA, err := manifest.EncodeIndex(rootIndex, agebox.X25519RecipientProvider{Strings: ixRecipients})
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}
	rootBody.IndexSHA256 = ixSHA
	tree[rootNodeID] = rootBody

	signer := bundle.Ed25519FileSigner{Path: signKeyPath}
	signedRoot, err := manifest.SignBody(rootBody, signer)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}
	mRecipients, err := manifest.RecipientSet(manifest.ArtifactManifest, rootNodeID, "", tree, nil, recovery)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}
	mCT, _, err := manifest.EncodeManifest(manifest.ManifestFile{Body: signedRoot, Recipients: mRecipients}, agebox.X25519RecipientProvider{Strings: mRecipients})
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}

	root := manifest.StoreRoot{
		Schema: manifest.Schema, StoreID: storeID, CreatedAt: createdAt,
		Format:     manifest.DefaultStoreFormat(),
		GitHub:     manifest.StoreGitHub{Owner: f.owner, Repo: f.repo, DefaultBranch: "main"},
		RootNodeID: rootNodeID,
		TrustAnchors: []manifest.TrustAnchor{
			{IID: founderID, SignPubkey: signPub},
		},
		Recovery: []manifest.RecoveryKey{{AgeRecipient: recoveryRecipient, SignPubkey: recoverySignPub}},
	}
	rootDoc, rootSig, err := manifest.SignStoreRoot(root, signer)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}

	repoDir := config.RepoDir(home)
	if err := writeRepoFile(storeRootPath(repoDir), rootDoc); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	if err := writeRepoFile(storeRootSigPath(repoDir), rootSig); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	if err := writeIdentityRecord(repoDir, manifest.IdentityRecord{
		Schema: manifest.Schema, ID: founderID, AgeRecipient: recipient,
		SSHEd25519Pubkey: signPub, CreatedAt: createdAt,
	}); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	if err := writeRepoFile(manifest.ObjectPath(objectsDir(repoDir), rootNodeID), mCT); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	if err := writeRepoFile(manifest.ObjectPath(objectsDir(repoDir), rootIndexID), ixCT); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}

	author := gitstore.Author{Name: defaultAuthorName, Email: defaultAuthorMail}
	if err := store.CommitAndPush(ctx, "kauket: initialize store", author); err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: commit and push: %w", err)}
	}

	adminCfg := &config.Admin{
		Schema:  config.ConfigSchema,
		Role:    config.RoleAdmin,
		StoreID: storeID,
		Repo:    config.DefaultRepoInfo(f.owner, f.repo),
		Admin: config.AdminInfo{
			RecipientID:  founderID,
			IdentityPath: filepath.Join("identities", "admin.txt"),
		},
		CommitAuthor: config.CommitAuthor{Name: defaultAuthorName, Email: defaultAuthorMail},
		V2:           &config.V2Local{IdentityID: founderID, SignKeyPath: filepath.Join("identities", "sign.key")},
	}
	if !useGitHub {
		adminCfg.Repo.RemoteHTTPS = remoteURL
		adminCfg.Repo.RemoteSSH = ""
	}
	if err := config.SaveAdmin(home, adminCfg); err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: save admin config: %w", err)}
	}

	pins := &manifest.Pins{
		StoreID:      storeID,
		TrustAnchors: root.TrustAnchors,
		NodeVersions: map[string]int{rootNodeID: 1},
		UpdatedAt:    createdAt,
	}
	for _, r := range root.Recovery {
		pins.RecoverySignPubkeys = append(pins.RecoverySignPubkeys, r.SignPubkey)
	}
	if err := manifest.SavePins(config.PinsPath(home), pins); err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}

	a.UI.Println(fmt.Sprintf("initialized kauket v2 store %s/%s", f.owner, f.repo))
	a.UI.Println(fmt.Sprintf("founder identity %s created", founderID))
	a.UI.Println(fmt.Sprintf("recovery key pair written to %s", f.recoveryOut))
	a.UI.Println("move the recovery keys OFFLINE now; they can decrypt every secret in this store")
	return nil
}
