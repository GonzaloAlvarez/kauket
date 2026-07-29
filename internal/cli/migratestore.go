package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"github.com/gonzaloalvarez/kauket/internal/githubauth"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	"github.com/gonzaloalvarez/kauket/internal/manifest"
	"github.com/gonzaloalvarez/kauket/internal/model"
	"github.com/spf13/cobra"
)

type migrateStoreFlags struct {
	recoveryOut string
	yes         bool
	purgeV1     bool
}

func NewMigrateStore(a *app.App) *cobra.Command {
	f := &migrateStoreFlags{}
	cmd := &cobra.Command{
		Use:   "migrate-store",
		Short: "Convert a v1 vault+bundle store to the v2 namespace store",
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.purgeV1 {
				return runPurgeV1(cmd.Context(), a, f)
			}
			return runMigrateStore(cmd.Context(), a, f)
		},
	}
	cmd.Flags().StringVar(&f.recoveryOut, "recovery-out", "", "Directory to write the offline recovery key pair (required)")
	cmd.Flags().BoolVar(&f.yes, "yes", false, "noninteractive")
	cmd.Flags().BoolVar(&f.purgeV1, "purge-v1", false, "delete the frozen v1 vault and bundles from an already-migrated store")
	return cmd
}

func runPurgeV1(ctx context.Context, a *app.App, f *migrateStoreFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	home, err := requireRoleHome(a, config.RoleAdmin, "kauket migrate-store")
	if err != nil {
		return err
	}
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if cfg.V2 == nil || cfg.V2.SignKeyPath == "" {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: --purge-v1 requires a migrated v2 store")}
	}
	if !f.yes {
		ok, err := a.UI.Confirm("permanently delete the frozen v1 vault and bundles? un-upgraded clients will stop working")
		if err != nil {
			return &ExitError{Code: ExitUsage, Err: err}
		}
		if !ok {
			return nil
		}
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
	store, err := newStore(ctx, gitstore.Config{RepoPath: config.RepoDir(home), URL: remoteURL, LockPath: config.LockPath(home), Now: now}, transport)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	defer store.Close()
	if err := store.Sync(ctx); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	repoDir := config.RepoDir(home)
	if !isV2Store(repoDir) {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: not a v2 store")}
	}

	for _, p := range []string{filepath.Join(repoDir, "repo.json"), filepath.Join(repoDir, "admin"), filepath.Join(repoDir, "bundles")} {
		if err := os.RemoveAll(p); err != nil {
			return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: remove %s: %w", p, err)}
		}
	}
	signKeyPath := cfg.V2.SignKeyPath
	if !filepath.IsAbs(signKeyPath) {
		signKeyPath = filepath.Join(home, signKeyPath)
	}
	if err := rewriteStoreRoot(repoDir, signKeyPath, func(root *manifest.StoreRoot) error {
		root.FrozenV1 = false
		return nil
	}); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}

	author := gitstore.Author{Name: cfg.CommitAuthor.Name, Email: cfg.CommitAuthor.Email}
	if err := store.CommitAndPush(ctx, "kauket: purge v1 store", author); err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: commit and push: %w", err)}
	}
	a.UI.Println("purged v1 vault and bundles; store is now v2-only")
	return nil
}

type migNode struct {
	id       string
	name     string
	path     []string
	children []*migNode
	entries  map[string]*migEntry
}

type migEntry struct {
	secretID string
	secret   model.Secret
	readers  map[string]bool
}

func runMigrateStore(ctx context.Context, a *app.App, f *migrateStoreFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if f.recoveryOut == "" {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: migrate-store requires --recovery-out <dir> for the offline recovery key pair")}
	}
	home, err := requireRoleHome(a, config.RoleAdmin, "kauket migrate-store")
	if err != nil {
		return err
	}
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if !f.yes {
		ok, err := a.UI.Confirm("convert this store to the v2 namespace format?")
		if err != nil {
			return &ExitError{Code: ExitUsage, Err: err}
		}
		if !ok {
			return nil
		}
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
	if isV2Store(repoDir) {
		a.UI.Println("already migrated")
		return nil
	}

	identityPath := cfg.Admin.IdentityPath
	if !filepath.IsAbs(identityPath) {
		identityPath = filepath.Join(home, identityPath)
	}
	vaultPath := filepath.Join(repoDir, "admin", "vault.age")
	vaultCT, err := os.ReadFile(vaultPath)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: read admin vault: %w", err)}
	}
	vault, err := bundle.DecodeVault(vaultCT, agebox.FileIdentityProvider{Path: identityPath})
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: decrypt admin vault: %w", err)}
	}

	frozenHashes, err := snapshotV1Files(repoDir)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
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
	recovery := []string{recoveryRecipient}

	founderRecipient := ""
	for _, ar := range vault.Admins {
		founderRecipient = ar.Recipient
		break
	}
	if founderRecipient == "" {
		return &ExitError{Code: ExitCrypto, Err: errors.New("kauket: vault has no admin recipients")}
	}
	founderID := model.NewIdentityID()
	createdAt := now().UTC().Format(time.RFC3339)

	oracle := map[string]map[string]model.BundleSecret{}
	hostIDs := make([]string, 0, len(vault.Hosts))
	for hostID := range vault.Hosts {
		hostIDs = append(hostIDs, hostID)
	}
	sort.Strings(hostIDs)
	for _, hostID := range hostIDs {
		b, err := bundle.BuildHostBundle(vault, hostID, now(), 1)
		if err != nil {
			return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: oracle bundle for %s: %w", hostID, err)}
		}
		oracle[hostID] = b.Secrets
	}

	root := buildMigTree(vault, oracle)
	assignMigIDs(root)

	founder := manifest.Owner{IID: founderID, AgeRecipient: founderRecipient, SignPubkey: signPub}
	tree := manifest.Tree{}
	indexes := map[string]*manifest.Index{}
	buildMigBodies(root, vault, founder, tree, indexes, createdAt)

	storeID := vault.StoreID
	if storeID == "" {
		storeID = cfg.StoreID
	}

	staged := map[string][]byte{}
	for nodeID, ix := range indexes {
		ix.StoreID = storeID
		node := tree[nodeID]
		node.StoreID = storeID
		tree[nodeID] = node
		for name, entry := range ix.Entries {
			me := findMigEntry(root, nodeID, name)
			obj := manifest.Object{
				Schema:        manifest.Schema,
				Kind:          orDefault(me.secret.Kind, "file"),
				StoreID:       storeID,
				ObjectID:      entry.ObjectID,
				Install:       me.secret.Install,
				ContentBase64: me.secret.ContentBase64,
				SHA256:        me.secret.SHA256,
				CreatedAt:     orDefault(me.secret.CreatedAt, createdAt),
				UpdatedAt:     orDefault(me.secret.UpdatedAt, createdAt),
			}
			objRecipients, err := manifest.RecipientSet(manifest.ArtifactObject, nodeID, name, tree, ix, recovery)
			if err != nil {
				return &ExitError{Code: ExitCrypto, Err: err}
			}
			ct, sha, err := manifest.EncodeObject(obj, agebox.X25519RecipientProvider{Strings: objRecipients})
			if err != nil {
				return &ExitError{Code: ExitCrypto, Err: err}
			}
			entry.ObjectSHA256 = sha
			entry.Kind = obj.Kind
			ix.Entries[name] = entry
			staged[entry.ObjectID] = ct
		}
		ixRecipients, err := manifest.RecipientSet(manifest.ArtifactIndex, nodeID, "", tree, nil, recovery)
		if err != nil {
			return &ExitError{Code: ExitCrypto, Err: err}
		}
		ixCT, ixSHA, err := manifest.EncodeIndex(*ix, agebox.X25519RecipientProvider{Strings: ixRecipients})
		if err != nil {
			return &ExitError{Code: ExitCrypto, Err: err}
		}
		node = tree[nodeID]
		node.IndexSHA256 = ixSHA
		tree[nodeID] = node
		staged[node.IndexObjectID] = ixCT
	}

	signer := bundle.Ed25519FileSigner{Path: signKeyPath}
	for nodeID, body := range tree {
		signed, err := manifest.SignBody(body, signer)
		if err != nil {
			return &ExitError{Code: ExitCrypto, Err: err}
		}
		mRecipients, err := manifest.RecipientSet(manifest.ArtifactManifest, nodeID, "", tree, nil, recovery)
		if err != nil {
			return &ExitError{Code: ExitCrypto, Err: err}
		}
		ct, _, err := manifest.EncodeManifest(manifest.ManifestFile{Body: signed, Recipients: mRecipients}, agebox.X25519RecipientProvider{Strings: mRecipients})
		if err != nil {
			return &ExitError{Code: ExitCrypto, Err: err}
		}
		staged[nodeID] = ct
	}

	storeRoot := manifest.StoreRoot{
		Schema: manifest.Schema, StoreID: storeID, CreatedAt: createdAt,
		Format:       manifest.DefaultStoreFormat(),
		GitHub:       manifest.StoreGitHub{Owner: cfg.Repo.Owner, Repo: cfg.Repo.Name, DefaultBranch: cfg.Repo.DefaultBranch},
		RootNodeID:   root.id,
		TrustAnchors: []manifest.TrustAnchor{{IID: founderID, SignPubkey: signPub, AgeRecipient: founderRecipient}},
		Recovery:     []manifest.RecoveryKey{{AgeRecipient: recoveryRecipient, SignPubkey: recoverySignPub}},
		FrozenV1:     true,
	}
	rootDoc, rootSig, err := manifest.SignStoreRoot(storeRoot, signer)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}

	identityRecords := []manifest.IdentityRecord{{
		Schema: manifest.Schema, ID: founderID, AgeRecipient: founderRecipient,
		SSHEd25519Pubkey: signPub, CreatedAt: createdAt,
	}}
	hostPubkeys := fetchHostPubkeys(ctx, a, cfg, remoteURL, hostIDs)
	for _, hostID := range hostIDs {
		identityRecords = append(identityRecords, manifest.IdentityRecord{
			Schema: manifest.Schema, ID: hostID,
			AgeRecipient:         vault.Hosts[hostID].AgeRecipient,
			SSHEd25519Pubkey:     hostPubkeys[hostID],
			DeployKeyFingerprint: vault.Hosts[hostID].DeployKeyFingerprint,
			CreatedAt:            orDefault(vault.Hosts[hostID].CreatedAt, createdAt),
		})
	}

	if err := writeRepoFile(storeRootPath(repoDir), rootDoc); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	if err := writeRepoFile(storeRootSigPath(repoDir), rootSig); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	for _, rec := range identityRecords {
		if err := writeIdentityRecord(repoDir, rec); err != nil {
			return &ExitError{Code: ExitSync, Err: err}
		}
	}
	for id, ct := range staged {
		if err := writeRepoFile(manifest.ObjectPath(objectsDir(repoDir), id), ct); err != nil {
			return &ExitError{Code: ExitSync, Err: err}
		}
	}

	if err := verifyMigration(a, repoDir, storeRoot, tree, indexes, root, oracle, frozenHashes, f.recoveryOut, home, cfg); err != nil {
		_ = store.Sync(ctx)
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: migration self-verification failed, nothing pushed: %w", err)}
	}

	author := gitstore.Author{Name: cfg.CommitAuthor.Name, Email: cfg.CommitAuthor.Email}
	if err := store.CommitAndPush(ctx, "kauket: migrate store", author); err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: commit and push: %w", err)}
	}

	cfg.V2 = &config.V2Local{IdentityID: founderID, SignKeyPath: filepath.Join("identities", "sign.key")}
	if err := config.SaveAdmin(home, cfg); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	pins := &manifest.Pins{StoreID: storeID, TrustAnchors: storeRoot.TrustAnchors, NodeVersions: map[string]int{}, UpdatedAt: createdAt}
	for _, r := range storeRoot.Recovery {
		pins.RecoverySignPubkeys = append(pins.RecoverySignPubkeys, r.SignPubkey)
	}
	for id := range tree {
		pins.NodeVersions[id] = 1
	}
	if err := manifest.SavePins(config.PinsPath(home), pins); err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}

	printMigrationReport(a, vault, root, hostIDs)
	a.UI.Println(fmt.Sprintf("migrated store %s to schema 2 (%d nodes, %d identities)", storeID, len(tree), len(identityRecords)))
	a.UI.Println(fmt.Sprintf("recovery key pair written to %s", f.recoveryOut))
	a.UI.Println("move the recovery keys OFFLINE now; they can decrypt every secret in this store")
	return nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func snapshotV1Files(repoDir string) (map[string]string, error) {
	out := map[string]string{}
	paths := []string{filepath.Join(repoDir, "repo.json"), filepath.Join(repoDir, "admin", "vault.age")}
	bundleDir := filepath.Join(repoDir, "bundles")
	entries, err := os.ReadDir(bundleDir)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				paths = append(paths, filepath.Join(bundleDir, e.Name()))
			}
		}
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("kauket: snapshot %s: %w", p, err)
		}
		sum := sha256.Sum256(data)
		out[p] = hex.EncodeToString(sum[:])
	}
	return out, nil
}

func buildMigTree(vault model.Vault, oracle map[string]map[string]model.BundleSecret) *migNode {
	root := &migNode{entries: map[string]*migEntry{}}
	secretIDs := make([]string, 0, len(vault.Secrets))
	for id := range vault.Secrets {
		secretIDs = append(secretIDs, id)
	}
	sort.Strings(secretIDs)
	for _, secretID := range secretIDs {
		segments := strings.Split(secretID, ".")
		nodePath := segments[:len(segments)-1]
		entryName := segments[len(segments)-1]
		node := root
		for depth, seg := range nodePath {
			var next *migNode
			for _, c := range node.children {
				if c.name == seg {
					next = c
					break
				}
			}
			if next == nil {
				next = &migNode{name: seg, path: append(append([]string{}, nodePath[:depth]...), seg), entries: map[string]*migEntry{}}
				node.children = append(node.children, next)
			}
			node = next
		}
		readers := map[string]bool{}
		for hostID, secrets := range oracle {
			if _, ok := secrets[secretID]; ok {
				readers[hostID] = true
			}
		}
		node.entries[entryName] = &migEntry{secretID: secretID, secret: vault.Secrets[secretID], readers: readers}
	}
	return root
}

func assignMigIDs(node *migNode) {
	node.id = model.NewNodeID()
	for _, c := range node.children {
		assignMigIDs(c)
	}
}

func buildMigBodies(node *migNode, vault model.Vault, founder manifest.Owner, tree manifest.Tree, indexes map[string]*manifest.Index, createdAt string) {
	nodeReaders := map[string]bool{}
	if len(node.entries) > 0 {
		first := true
		for _, e := range node.entries {
			if first {
				for h := range e.readers {
					nodeReaders[h] = true
				}
				first = false
				continue
			}
			for h := range nodeReaders {
				if !e.readers[h] {
					delete(nodeReaders, h)
				}
			}
		}
	}

	var readers []manifest.Member
	readerIDs := make([]string, 0, len(nodeReaders))
	for h := range nodeReaders {
		readerIDs = append(readerIDs, h)
	}
	sort.Strings(readerIDs)
	for _, h := range readerIDs {
		readers = append(readers, manifest.Member{IID: h, AgeRecipient: vault.Hosts[h].AgeRecipient})
	}

	ix := &manifest.Index{Schema: manifest.Schema, Kind: manifest.KindIndex, NodeID: node.id, Entries: map[string]manifest.IndexEntry{}}
	extraSet := map[string]bool{}
	entryNames := make([]string, 0, len(node.entries))
	for name := range node.entries {
		entryNames = append(entryNames, name)
	}
	sort.Strings(entryNames)
	for _, name := range entryNames {
		e := node.entries[name]
		var entryReaders []manifest.Member
		residualIDs := make([]string, 0, len(e.readers))
		for h := range e.readers {
			if !nodeReaders[h] {
				residualIDs = append(residualIDs, h)
			}
		}
		sort.Strings(residualIDs)
		for _, h := range residualIDs {
			entryReaders = append(entryReaders, manifest.Member{IID: h, AgeRecipient: vault.Hosts[h].AgeRecipient})
			extraSet[h] = true
		}
		ix.Entries[name] = manifest.IndexEntry{
			ObjectID:  model.NewObjectID(),
			Readers:   entryReaders,
			CreatedAt: orDefault(e.secret.CreatedAt, createdAt),
			UpdatedAt: orDefault(e.secret.UpdatedAt, createdAt),
		}
	}
	var extraReaders []manifest.Member
	extraIDs := make([]string, 0, len(extraSet))
	for h := range extraSet {
		extraIDs = append(extraIDs, h)
	}
	sort.Strings(extraIDs)
	for _, h := range extraIDs {
		extraReaders = append(extraReaders, manifest.Member{IID: h, AgeRecipient: vault.Hosts[h].AgeRecipient})
	}

	var children []manifest.ChildAttestation
	sort.Slice(node.children, func(i, j int) bool { return node.children[i].name < node.children[j].name })
	for _, c := range node.children {
		children = append(children, manifest.ChildAttestation{NodeID: c.id, OwnerSignKeys: []string{founder.SignPubkey}})
	}

	parentID := ""
	body := manifest.ManifestBody{
		Schema: manifest.Schema, Kind: manifest.KindManifest,
		NodeID: node.id, Version: 1, UpdatedAt: createdAt,
		Name: node.name, ParentID: parentID,
		Children:      children,
		Owners:        []manifest.Owner{founder},
		Readers:       readers,
		ExtraReaders:  extraReaders,
		IndexObjectID: model.NewIndexObjectID(),
	}
	tree[node.id] = body
	indexes[node.id] = ix

	for _, c := range node.children {
		buildMigBodies(c, vault, founder, tree, indexes, createdAt)
		childBody := tree[c.id]
		childBody.ParentID = node.id
		tree[c.id] = childBody
	}
}

func findMigEntry(root *migNode, nodeID, name string) *migEntry {
	if root.id == nodeID {
		return root.entries[name]
	}
	for _, c := range root.children {
		if e := findMigEntry(c, nodeID, name); e != nil {
			return e
		}
	}
	return nil
}

func fetchHostPubkeys(ctx context.Context, a *app.App, cfg *config.Admin, remoteURL string, hostIDs []string) map[string]string {
	out := map[string]string{}
	if strings.HasPrefix(remoteURL, "file://") {
		return out
	}
	token, _, err := githubauth.Select(ctx, []string{"repo"}, githubauth.SelectorOptions{
		Shell:           a.AuthShell,
		ClientID:        githubauth.ClientID,
		Account:         cfg.Repo.Owner,
		HTTPClient:      a.HTTPClient,
		AllowDeviceFlow: true,
	})
	if err != nil {
		return out
	}
	manager := &gitstore.DeployKeyManager{Owner: cfg.Repo.Owner, Repo: cfg.Repo.Name, Token: token, HTTPClient: a.HTTPClient}
	keys, err := manager.List(ctx)
	if err != nil {
		return out
	}
	for _, k := range keys {
		for _, hostID := range hostIDs {
			if k.Title == "kauket "+hostID {
				out[hostID] = strings.TrimSpace(k.Key)
			}
		}
	}
	return out
}

func verifyMigration(a *app.App, repoDir string, storeRoot manifest.StoreRoot, tree manifest.Tree, indexes map[string]*manifest.Index, root *migNode, oracle map[string]map[string]model.BundleSecret, frozenHashes map[string]string, recoveryOut, home string, cfg *config.Admin) error {
	doc, err := os.ReadFile(storeRootPath(repoDir))
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(storeRootSigPath(repoDir))
	if err != nil {
		return err
	}
	anchorKeys := make([]string, 0, 2)
	for _, t := range storeRoot.TrustAnchors {
		anchorKeys = append(anchorKeys, t.SignPubkey)
	}
	if _, err := manifest.VerifyStoreRoot(doc, sig, anchorKeys, bundle.Ed25519Verifier{}); err != nil {
		return fmt.Errorf("store root verification: %w", err)
	}

	recoveryIP := agebox.FileIdentityProvider{Path: filepath.Join(recoveryOut, "recovery-age.txt")}
	dirEntries, err := os.ReadDir(objectsDir(repoDir))
	if err != nil {
		return err
	}
	for _, e := range dirEntries {
		ct, err := os.ReadFile(filepath.Join(objectsDir(repoDir), e.Name()))
		if err != nil {
			return err
		}
		if _, err := agebox.Decrypt(ct, recoveryIP); err != nil {
			return fmt.Errorf("recovery cannot decrypt %s: %w", e.Name(), err)
		}
	}

	identityPath := cfg.Admin.IdentityPath
	if !filepath.IsAbs(identityPath) {
		identityPath = filepath.Join(home, identityPath)
	}
	founderIP := agebox.FileIdentityProvider{Path: identityPath}
	freshPins := &manifest.Pins{NodeVersions: map[string]int{}}
	nodes, err := manifest.LoadReadableTree(objectsDir(repoDir), storeRoot, freshPins, founderIP, bundle.Ed25519Verifier{})
	if err != nil {
		return fmt.Errorf("founder tree walk: %w", err)
	}
	if len(nodes) != len(tree) {
		return fmt.Errorf("founder reads %d nodes, staged %d", len(nodes), len(tree))
	}
	loadedIndexes := map[string]*manifest.Index{}
	loadedObjects := map[string]map[string]manifest.Object{}
	for id, f := range nodes {
		if f.Body.Version != 1 {
			return fmt.Errorf("node %s version %d, want 1", id, f.Body.Version)
		}
		ix, err := manifest.LoadIndex(objectsDir(repoDir), f.Body, founderIP)
		if err != nil {
			return fmt.Errorf("index of %s: %w", id, err)
		}
		loadedIndexes[id] = ix
		loadedObjects[id] = map[string]manifest.Object{}
		for name, entry := range ix.Entries {
			obj, err := manifest.LoadObject(objectsDir(repoDir), entry, founderIP)
			if err != nil {
				return fmt.Errorf("object %s/%s: %w", id, name, err)
			}
			content, err := base64.StdEncoding.DecodeString(obj.ContentBase64)
			if err != nil {
				return fmt.Errorf("content decode %s/%s: %w", id, name, err)
			}
			sum := sha256.Sum256(content)
			if hex.EncodeToString(sum[:]) != obj.SHA256 {
				return fmt.Errorf("content hash mismatch %s/%s", id, name)
			}
			loadedObjects[id][name] = obj
		}
	}

	bodies := map[string]manifest.ManifestBody{}
	for id, f := range nodes {
		bodies[id] = f.Body
	}
	for hostID, oracleSecrets := range oracle {
		v2Set := collectHostReadSet(bodies, loadedIndexes, loadedObjects, hostID)
		if len(v2Set) != len(oracleSecrets) {
			return fmt.Errorf("host %s: v2 read set has %d secrets, v1 bundle has %d", hostID, len(v2Set), len(oracleSecrets))
		}
		for secretID, v1secret := range oracleSecrets {
			obj, ok := v2Set[secretID]
			if !ok {
				return fmt.Errorf("host %s: secret %s missing from v2 read set", hostID, secretID)
			}
			if obj.ContentBase64 != v1secret.ContentBase64 {
				return fmt.Errorf("host %s: secret %s content differs", hostID, secretID)
			}
			if obj.SHA256 != v1secret.SHA256 {
				return fmt.Errorf("host %s: secret %s sha differs", hostID, secretID)
			}
			if obj.Install != v1secret.Install {
				return fmt.Errorf("host %s: secret %s install spec differs", hostID, secretID)
			}
			if obj.Kind != orDefault(v1secret.Kind, "file") {
				return fmt.Errorf("host %s: secret %s kind differs", hostID, secretID)
			}
		}
	}

	current, err := snapshotV1Files(repoDir)
	if err != nil {
		return err
	}
	for p, h := range frozenHashes {
		if current[p] != h {
			return fmt.Errorf("frozen v1 file changed: %s", p)
		}
	}
	return nil
}

func collectHostReadSet(bodies map[string]manifest.ManifestBody, indexes map[string]*manifest.Index, objects map[string]map[string]manifest.Object, hostID string) map[string]manifest.Object {
	pathCache := map[string]string{}
	var pathOf func(id string) string
	pathOf = func(id string) string {
		if p, ok := pathCache[id]; ok {
			return p
		}
		body := bodies[id]
		p := body.Name
		if body.ParentID != "" {
			parentPath := pathOf(body.ParentID)
			if parentPath != "" {
				p = parentPath + "." + body.Name
			}
		}
		pathCache[id] = p
		return p
	}
	memberOf := func(id string) bool {
		body := bodies[id]
		for _, o := range body.Owners {
			if o.IID == hostID {
				return true
			}
		}
		for _, r := range body.Readers {
			if r.IID == hostID {
				return true
			}
		}
		return false
	}
	out := map[string]manifest.Object{}
	for id, ix := range indexes {
		nodeMember := memberOf(id)
		prefix := pathOf(id)
		for name, entry := range ix.Entries {
			granted := nodeMember
			if !granted {
				for _, r := range entry.Readers {
					if r.IID == hostID {
						granted = true
						break
					}
				}
			}
			if !granted {
				continue
			}
			full := name
			if prefix != "" {
				full = prefix + "." + name
			}
			out[full] = objects[id][name]
		}
	}
	return out
}

func printMigrationReport(a *app.App, vault model.Vault, root *migNode, hostIDs []string) {
	a.UI.Println("profile materialization:")
	for _, hostID := range hostIDs {
		host := vault.Hosts[hostID]
		grants := append(append([]string{}, host.GrantedProfiles...), host.GrantedSecrets...)
		a.UI.Println(fmt.Sprintf("  %s (%s): %s", hostID, host.DisplayName, strings.Join(grants, ", ")))
	}
}
