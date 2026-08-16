package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"filippo.io/age"
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

func enforceAnchorPin(a *app.App, root *manifest.StoreRoot, expected string) error {
	expected = strings.TrimSpace(expected)
	var fprs []string
	for _, t := range root.TrustAnchors {
		fpr, err := manifest.SignKeyFingerprint(t.SignPubkey)
		if err != nil {
			continue
		}
		fprs = append(fprs, fpr)
	}
	if expected != "" {
		for _, f := range fprs {
			if f == expected || strings.HasSuffix(f, expected) {
				return nil
			}
		}
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: no trust anchor matches the expected anchor %q; refusing to pin (store anchors: %s)", expected, strings.Join(fprs, ", "))}
	}
	for _, f := range fprs {
		a.UI.Println(fmt.Sprintf("warning: trust-on-first-use: pinning store anchor %s (confirm out of band with the store operator, or set KAUKET_ANCHOR)", f))
	}
	return nil
}

func fetchStoreDoc(ctx context.Context, a *app.App, remoteURL string, transport gitstore.Transport, now func() time.Time, expectedAnchor string) (*manifest.StoreRoot, error) {
	tempDir, err := os.MkdirTemp("", "kauket-fetch-")
	if err != nil {
		return nil, fmt.Errorf("kauket: temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	repoPath := filepath.Join(tempDir, "repo")
	newStore := a.NewStore
	if newStore == nil {
		newStore = gitstore.OpenOrClone
	}
	if transport == nil {
		transport = gitstore.SelectTransport(remoteURL, "")
	}
	store, err := newStore(ctx, gitstore.Config{
		RepoPath: repoPath,
		URL:      remoteURL,
		LockPath: filepath.Join(tempDir, "repo.lock"),
		Now:      now,
	}, transport)
	if err != nil {
		return nil, fmt.Errorf("kauket: open remote for fetch: %w", err)
	}
	defer store.Close()
	if err := store.Sync(ctx); err != nil {
		return nil, fmt.Errorf("kauket: sync remote: %w", err)
	}

	if !isV2Store(repoPath) {
		return nil, errors.New("kauket: this remote does not hold a v2 kauket store; migrate legacy v1 stores with the kauket v2.0.x release")
	}
	doc, err := os.ReadFile(storeRootPath(repoPath))
	if err != nil {
		return nil, fmt.Errorf("kauket: read store.json: %w", err)
	}
	sig, err := os.ReadFile(storeRootSigPath(repoPath))
	if err != nil {
		return nil, fmt.Errorf("kauket: read store.json.sig: %w", err)
	}
	var raw manifest.StoreRoot
	if err := json.Unmarshal(doc, &raw); err != nil {
		return nil, fmt.Errorf("kauket: parse store.json: %w", err)
	}
	selfKeys := make([]string, 0, len(raw.TrustAnchors)+len(raw.Recovery))
	for _, t := range raw.TrustAnchors {
		selfKeys = append(selfKeys, t.SignPubkey)
	}
	for _, r := range raw.Recovery {
		selfKeys = append(selfKeys, r.SignPubkey)
	}
	root, _, err := manifest.VerifyStoreRoot(doc, sig, selfKeys, bundle.Ed25519Verifier{})
	if err != nil {
		return nil, err
	}
	if err := enforceAnchorPin(a, &root, expectedAnchor); err != nil {
		return nil, err
	}
	return &root, nil
}

func anchorRecipients(root *manifest.StoreRoot) []string {
	var out []string
	for _, t := range root.TrustAnchors {
		if t.AgeRecipient != "" {
			out = append(out, t.AgeRecipient)
		}
	}
	return out
}

func recipientOfIdentityFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("kauket: read identity: %w", err)
	}
	ids, err := agebox.ParseIdentity(data)
	if err != nil {
		return "", err
	}
	if len(ids) != 1 {
		return "", fmt.Errorf("kauket: identity file must contain exactly one identity, found %d", len(ids))
	}
	x, ok := ids[0].(*age.X25519Identity)
	if !ok {
		return "", errors.New("kauket: identity must be an X25519 identity")
	}
	return x.Recipient().String(), nil
}

func requestPaths(pathArgs []string, key string) ([]string, error) {
	if key != "" && len(pathArgs) > 1 {
		return nil, errors.New("kauket: --key requires a single path")
	}
	var paths []string
	for _, p := range pathArgs {
		segs := splitNodePath(p)
		if len(segs) == 0 {
			continue
		}
		if key != "" {
			segs = append(segs, key)
		}
		paths = append(paths, strings.Join(segs, "/"))
	}
	if len(paths) == 0 {
		return nil, errors.New("kauket: empty request path")
	}
	return paths, nil
}

func resolveExplicitRemote(repoFlag, remoteFlag string) (string, string, string, bool, error) {
	remoteFlag = strings.TrimSpace(remoteFlag)
	if remoteFlag != "" {
		owner, repoName := splitOwnerRepo(repoFlag)
		if owner == "" || repoName == "" {
			owner, repoName = inferOwnerRepoFromRemote(remoteFlag)
		}
		if repoName == "" {
			repoName = defaultRepoName
		}
		return owner, repoName, remoteFlag, true, nil
	}
	src := strings.TrimSpace(repoFlag)
	if src == "" {
		src = strings.TrimSpace(config.EnvRepo())
	}
	if src == "" {
		return "", "", "", false, nil
	}
	owner, repoName := splitOwnerRepo(src)
	if owner == "" || repoName == "" {
		return "", "", "", false, fmt.Errorf("kauket: invalid owner/repo %q; expected owner/repo", src)
	}
	return owner, repoName, fmt.Sprintf("https://github.com/%s/%s.git", owner, repoName), true, nil
}

func resolveRequestRemote(ctx context.Context, a *app.App, f *requestFlags) (owner, repoName, remoteURL, token string, detected bool, err error) {
	owner, repoName, remoteURL, explicit, err := resolveExplicitRemote(f.repo, f.remote)
	if err != nil {
		return "", "", "", "", false, err
	}
	if explicit {
		return owner, repoName, remoteURL, "", false, nil
	}
	owner, err = detectGitHubOwner(ctx, a)
	if err != nil {
		tok, _, authErr := githubauth.Select(ctx, []string{"repo"}, githubauth.SelectorOptions{
			Shell: a.AuthShell, ClientID: githubauth.ClientID,
			HTTPClient: a.HTTPClient, AllowDeviceFlow: true,
			PrintCode: func(verifyURL, userCode string) {
				a.UI.Println(fmt.Sprintf("open %s and enter code %s", verifyURL, userCode))
			},
		})
		if authErr != nil {
			return "", "", "", "", false, errors.New("kauket: could not detect your GitHub user; pass --repo owner/repo or --remote URL")
		}
		owner, err = githubUserLogin(ctx, a.HTTPClient, tok)
		if err != nil {
			return "", "", "", "", false, err
		}
		token = tok
	}
	repoName = defaultRepoName
	return owner, repoName, fmt.Sprintf("https://github.com/%s/%s.git", owner, repoName), token, true, nil
}

func autoEnrollRequest(ctx context.Context, a *app.App, pathArgs []string, f *requestFlags) error {
	home, _, err := resolveRoleHome(a, config.RoleClient)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: resolve home: %w", err)}
	}
	paths, err := requestPaths(pathArgs, f.key)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	owner, repoName, remoteURL, token, detected, err := resolveRequestRemote(ctx, a, f)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	a.UI.Println("not enrolled yet; enrolling this machine")
	if detected && !f.yes {
		ok, cerr := a.UI.Confirm(fmt.Sprintf("store repo: %s/%s — ok?", owner, repoName))
		if cerr != nil {
			return &ExitError{Code: ExitUsage, Err: cerr}
		}
		if !ok {
			return &ExitError{Code: ExitUsage, Err: errors.New("kauket: pass --repo owner/repo or --remote URL")}
		}
	}

	useGitHub := !strings.HasPrefix(remoteURL, "file://")
	if useGitHub && (strings.HasPrefix(remoteURL, "git@") || strings.HasPrefix(remoteURL, "ssh://")) {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: enrollment does not support SSH remotes; use an HTTPS GitHub URL or a file URL")}
	}

	if err := os.MkdirAll(home, 0o700); err != nil {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: create home: %w", err)}
	}
	if err := config.EnsureIdentitiesDir(home); err != nil {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: create identities dir: %w", err)}
	}
	if err := config.EnsureGitDir(home); err != nil {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: create git dir: %w", err)}
	}
	if err := config.EnsureStateDir(home); err != nil {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: create state dir: %w", err)}
	}

	hostRecipient, err := ensureHostIdentity(config.HostIdentityPath(home))
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}
	deployPub, err := ensureDeployKey(config.DeployKeyPath(home), config.DeployKeyPubPath(home))
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}

	var transport gitstore.Transport
	if !useGitHub {
		transport = gitstore.FileURLTransport{}
	} else if token != "" {
		transport = gitstore.HTTPSTokenTransport{Token: token}
	} else {
		tok, _, authErr := githubauth.Select(ctx, []string{"repo"}, githubauth.SelectorOptions{
			Shell: a.AuthShell, ClientID: githubauth.ClientID,
			HTTPClient: a.HTTPClient, AllowDeviceFlow: true,
			PrintCode: func(verifyURL, userCode string) {
				a.UI.Println(fmt.Sprintf("open %s and enter code %s", verifyURL, userCode))
			},
		})
		if authErr != nil {
			return &ExitError{Code: ExitSync, Err: authErr}
		}
		transport = gitstore.HTTPSTokenTransport{Token: tok}
	}

	now := a.Now
	if now == nil {
		now = time.Now
	}
	root, err := fetchStoreDoc(ctx, a, remoteURL, transport, now, os.Getenv("KAUKET_ANCHOR"))
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	if strings.TrimSpace(f.repo) == "" && root.GitHub.Owner != "" {
		owner = root.GitHub.Owner
		repoName = root.GitHub.Repo
	}

	recipients := anchorRecipients(root)
	if len(recipients) == 0 {
		return &ExitError{Code: ExitSync, Err: errors.New("kauket: store.json has no anchor age recipients")}
	}

	osHostname, _ := os.Hostname()
	displayName := strings.TrimSpace(f.name)
	if displayName == "" {
		displayName = shortHostname(osHostname)
	}
	hostID := model.NewHostID()
	requestID := model.NewRequestID()
	req := model.Request{
		Schema:    1,
		StoreID:   root.StoreID,
		RequestID: requestID,
		CreatedAt: now().UTC().Format(time.RFC3339),
		Host: model.RequestHost{
			ID:                 hostID,
			Kind:               "machine",
			DisplayName:        displayName,
			ReportedHostname:   osHostname,
			OS:                 runtime.GOOS,
			Arch:               runtime.GOARCH,
			AgeRecipient:       hostRecipient,
			GitDeployPublicKey: deployPub,
		},
		Requested: model.RequestedItems{Paths: paths},
	}
	signer := bundle.Ed25519FileSigner{Path: config.DeployKeyPath(home)}
	ct, err := bundle.EncodeRequest(req, signer, agebox.X25519RecipientProvider{Strings: recipients})
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: encode request: %w", err)}
	}
	syntheticAuthor := gitstore.Author{Name: "kauket-" + hostID, Email: "kauket@" + hostID + ".local"}

	if err := pushEnrollmentRequest(ctx, a, home, remoteURL, transport, requestID, ct, syntheticAuthor, now); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	a.UI.Println(fmt.Sprintf("enrolled as %s (%s)", displayName, hostID))
	a.UI.Println(fmt.Sprintf("created enrollment request %s", requestID))
	a.UI.Println(fmt.Sprintf("requested paths: %s", strings.Join(paths, ", ")))
	a.UI.Println("waiting for approval (run 'kauket approve' on your admin machine)")

	clientCfg := &config.Client{
		Schema:  config.ConfigSchema,
		Role:    config.RoleClient,
		StoreID: root.StoreID,
		Host: config.HostInfo{
			ID:            hostID,
			DisplayName:   displayName,
			IdentityPath:  filepath.Join("identities", "host.txt"),
			DeployKeyPath: filepath.Join("git", "deploy_key"),
		},
		Repo:         config.DefaultRepoInfo(owner, repoName),
		CommitAuthor: config.CommitAuthor{Name: syntheticAuthor.Name, Email: syntheticAuthor.Email},
	}
	if !useGitHub {
		clientCfg.Repo.RemoteHTTPS = remoteURL
		clientCfg.Repo.RemoteSSH = ""
	}
	if err := config.SaveClient(home, clientCfg); err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: save client config: %w", err)}
	}
	pins := &manifest.Pins{StoreID: root.StoreID, StoreVersion: root.Version, TrustAnchors: root.TrustAnchors, NodeVersions: map[string]int{}, UpdatedAt: now().UTC().Format(time.RFC3339)}
	for _, r := range root.Recovery {
		pins.RecoverySignPubkeys = append(pins.RecoverySignPubkeys, r.SignPubkey)
	}
	if err := manifest.SavePins(config.PinsPath(home), pins); err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	return nil
}

type requestFlags struct {
	key    string
	name   string
	repo   string
	remote string
	yes    bool
}

func NewRequest(a *app.App) *cobra.Command {
	f := &requestFlags{}
	cmd := &cobra.Command{
		Use:   "request <path>...",
		Short: "Request access to namespaces or a single key; enrolls this machine on first use",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRequest(cmd.Context(), a, args, f)
		},
	}
	cmd.Flags().StringVar(&f.key, "key", "", "request a single key inside the namespace (single path only)")
	cmd.Flags().StringVar(&f.name, "name", "", "host display name on first enrollment; defaults to short hostname")
	cmd.Flags().StringVar(&f.repo, "repo", "", "owner/repo of the store (first enrollment)")
	cmd.Flags().StringVar(&f.remote, "remote", "", "explicit Git remote URL (first enrollment)")
	cmd.Flags().BoolVar(&f.yes, "yes", false, "noninteractive")
	return cmd
}

func runRequest(ctx context.Context, a *app.App, pathArgs []string, f *requestFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	home, identityPath, v2, role, err := resolveV2ReadIdentity(a)
	if err != nil {
		return autoEnrollRequest(ctx, a, pathArgs, f)
	}
	if f.name != "" || f.repo != "" || f.remote != "" {
		a.UI.Println("already enrolled; ignoring --name/--repo/--remote")
	}
	paths, err := requestPaths(pathArgs, f.key)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	var identityID, signKeyPath, remoteURL string
	var repoInfo config.RepoInfo
	if role == config.RoleClient {
		cfg, err := config.LoadClient(home)
		if err != nil {
			return &ExitError{Code: ExitUsage, Err: err}
		}
		identityID = cfg.Host.ID
		signKeyPath = cfg.Host.DeployKeyPath
		repoInfo = cfg.Repo
	} else {
		cfg, err := config.LoadAdmin(home)
		if err != nil {
			return &ExitError{Code: ExitUsage, Err: err}
		}
		if cfg.V2 == nil {
			return &ExitError{Code: ExitUsage, Err: errors.New("kauket: this home has no v2 identity")}
		}
		identityID = cfg.V2.IdentityID
		signKeyPath = cfg.V2.SignKeyPath
		repoInfo = cfg.Repo
	}
	if err := syncForRead(ctx, a, role, home); err != nil {
		return err
	}
	if !filepath.IsAbs(signKeyPath) {
		signKeyPath = filepath.Join(home, signKeyPath)
	}
	if !isV2Store(config.RepoDir(home)) {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: request requires a v2 store")}
	}
	vctx, err := loadV2Context(home, identityPath, v2)
	if err != nil {
		return translateV2ReadError(err)
	}

	recipients := map[string]bool{}
	for _, r := range anchorRecipients(&vctx.root) {
		recipients[r] = true
	}
	for _, requestedPath := range paths {
		segments := splitNodePath(requestedPath)
		for probe := segments; len(probe) >= 0; probe = probe[:len(probe)-1] {
			res, err := manifest.WalkSpine(objectsDir(vctx.repoDir), vctx.root, vctx.pins, vctx.identity, bundle.Ed25519Verifier{}, probe)
			if err == nil {
				deepest := res.Nodes[res.SpineIDs[len(res.SpineIDs)-1]]
				for _, o := range deepest.Body.Owners {
					recipients[o.AgeRecipient] = true
				}
				break
			}
			if len(probe) == 0 {
				break
			}
		}
	}
	recipientList := make([]string, 0, len(recipients))
	for r := range recipients {
		recipientList = append(recipientList, r)
	}

	idRecipient, err := recipientOfIdentityFile(vctx.identity.Path)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}
	kind := "machine"
	if role == config.RoleAdmin {
		kind = "user"
	}
	osHostname, _ := os.Hostname()
	requestID := model.NewRequestID()
	now := a.Now
	if now == nil {
		now = time.Now
	}
	req := model.Request{
		Schema:    1,
		StoreID:   vctx.root.StoreID,
		RequestID: requestID,
		CreatedAt: now().UTC().Format(time.RFC3339),
		Host: model.RequestHost{
			ID:               identityID,
			Kind:             kind,
			DisplayName:      shortHostname(osHostname),
			ReportedHostname: osHostname,
			OS:               runtime.GOOS,
			Arch:             runtime.GOARCH,
			AgeRecipient:     idRecipient,
		},
		Requested: model.RequestedItems{Paths: paths},
	}
	pub, err := ensureSignKey(signKeyPath)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}
	req.Host.GitDeployPublicKey = pub
	ct, err := bundle.EncodeRequest(req, bundle.Ed25519FileSigner{Path: signKeyPath}, agebox.X25519RecipientProvider{Strings: recipientList})
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: encode request: %w", err)}
	}

	remoteURL = repoInfo.RemoteHTTPS
	useGitHub := !strings.HasPrefix(remoteURL, "file://")
	var transport gitstore.Transport
	if useGitHub {
		printCode := func(verifyURL, userCode string) {
			a.UI.Println(fmt.Sprintf("open %s and enter code %s", verifyURL, userCode))
		}
		tok, _, authErr := githubauth.Select(ctx, []string{"repo"}, githubauth.SelectorOptions{
			Shell: a.AuthShell, ClientID: githubauth.ClientID, PrintCode: printCode,
			HTTPClient: a.HTTPClient, AllowDeviceFlow: true,
		})
		if authErr != nil {
			return &ExitError{Code: ExitSync, Err: authErr}
		}
		transport = gitstore.HTTPSTokenTransport{Token: tok}
	} else {
		transport = gitstore.FileURLTransport{}
	}
	author := gitstore.Author{Name: "kauket-" + identityID, Email: "kauket@" + identityID + ".local"}
	if err := pushEnrollmentRequest(ctx, a, home, remoteURL, transport, requestID, ct, author, now); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	a.UI.Println(fmt.Sprintf("created access request %s", requestID))
	a.UI.Println(fmt.Sprintf("requested: %s", strings.Join(paths, ", ")))
	a.UI.Println("waiting for approval")
	return nil
}

type joinFlags struct {
	requests []string
	name     string
	repo     string
	remote   string
	yes      bool
	anchor   string
}

func NewJoin(a *app.App) *cobra.Command {
	f := &joinFlags{}
	cmd := &cobra.Command{
		Use:   "join",
		Short: "Join a v2 store as a human identity and request access",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runJoin(cmd.Context(), a, f)
		},
	}
	cmd.Flags().StringArrayVar(&f.requests, "request", nil, "repeatable; namespace path to request")
	cmd.Flags().StringVar(&f.name, "name", "", "display name; defaults to short hostname")
	cmd.Flags().StringVar(&f.repo, "repo", "", "owner/repo of the store")
	cmd.Flags().StringVar(&f.remote, "remote", "", "explicit Git remote URL")
	cmd.Flags().BoolVar(&f.yes, "yes", false, "noninteractive")
	cmd.Flags().StringVar(&f.anchor, "anchor", "", "expected store trust-anchor fingerprint (out-of-band); refuses to pin a different anchor")
	return cmd
}

func runJoin(ctx context.Context, a *app.App, f *joinFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	home, exists, err := resolveRoleHome(a, config.RoleAdmin)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if exists {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: already joined; remove %s to re-join", home)}
	}
	if len(f.requests) == 0 {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: at least one --request path is required")}
	}
	owner, repoName, remoteURL, explicit, err := resolveExplicitRemote(f.repo, f.remote)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if !explicit {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: --remote, --repo, or KAUKET_REPO is required")}
	}
	if err := config.EnsureIdentitiesDir(home); err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	identityPath := config.AdminIdentityPath(home)
	recipient, err := ensureAdminIdentity(identityPath)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}
	signKeyPath := filepath.Join(home, "identities", "sign.key")
	signPub, err := ensureSignKey(signKeyPath)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}

	useGitHub := !strings.HasPrefix(remoteURL, "file://")
	var transport gitstore.Transport
	if useGitHub {
		printCode := func(verifyURL, userCode string) {
			a.UI.Println(fmt.Sprintf("open %s and enter code %s", verifyURL, userCode))
		}
		tok, _, authErr := githubauth.Select(ctx, []string{"repo"}, githubauth.SelectorOptions{
			Shell: a.AuthShell, ClientID: githubauth.ClientID, PrintCode: printCode,
			HTTPClient: a.HTTPClient, AllowDeviceFlow: true,
		})
		if authErr != nil {
			return &ExitError{Code: ExitSync, Err: authErr}
		}
		transport = gitstore.HTTPSTokenTransport{Token: tok}
	} else {
		transport = gitstore.FileURLTransport{}
	}
	now := a.Now
	if now == nil {
		now = time.Now
	}
	expectedAnchor := f.anchor
	if expectedAnchor == "" {
		expectedAnchor = os.Getenv("KAUKET_ANCHOR")
	}
	root, err := fetchStoreDoc(ctx, a, remoteURL, transport, now, expectedAnchor)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}

	var paths []string
	for _, p := range f.requests {
		segs := splitNodePath(p)
		if len(segs) > 0 {
			paths = append(paths, strings.Join(segs, "/"))
		}
	}
	recipients := anchorRecipients(root)
	if len(recipients) == 0 {
		return &ExitError{Code: ExitSync, Err: errors.New("kauket: store.json has no anchor age recipients")}
	}

	osHostname, _ := os.Hostname()
	displayName := strings.TrimSpace(f.name)
	if displayName == "" {
		displayName = shortHostname(osHostname)
	}
	identityID := model.NewIdentityID()
	requestID := model.NewRequestID()
	req := model.Request{
		Schema:    1,
		StoreID:   root.StoreID,
		RequestID: requestID,
		CreatedAt: now().UTC().Format(time.RFC3339),
		Host: model.RequestHost{
			ID:                 identityID,
			Kind:               "user",
			DisplayName:        displayName,
			ReportedHostname:   osHostname,
			OS:                 runtime.GOOS,
			Arch:               runtime.GOARCH,
			AgeRecipient:       recipient,
			GitDeployPublicKey: signPub,
		},
		Requested: model.RequestedItems{Paths: paths},
	}
	ct, err := bundle.EncodeRequest(req, bundle.Ed25519FileSigner{Path: signKeyPath}, agebox.X25519RecipientProvider{Strings: recipients})
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: encode request: %w", err)}
	}
	author := gitstore.Author{Name: "kauket-" + identityID, Email: "kauket@" + identityID + ".local"}
	if err := pushEnrollmentRequest(ctx, a, home, remoteURL, transport, requestID, ct, author, now); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	a.UI.Println(fmt.Sprintf("created join request %s", requestID))
	a.UI.Println("waiting for approval")

	adminCfg := &config.Admin{
		Schema:  config.ConfigSchema,
		Role:    config.RoleAdmin,
		StoreID: root.StoreID,
		Repo:    config.DefaultRepoInfo(owner, repoName),
		Admin: config.AdminInfo{
			RecipientID:  identityID,
			IdentityPath: filepath.Join("identities", "admin.txt"),
		},
		CommitAuthor: config.CommitAuthor{Name: author.Name, Email: author.Email},
		V2:           &config.V2Local{IdentityID: identityID, SignKeyPath: filepath.Join("identities", "sign.key")},
	}
	if !useGitHub {
		adminCfg.Repo.RemoteHTTPS = remoteURL
		adminCfg.Repo.RemoteSSH = ""
	}
	if err := config.SaveAdmin(home, adminCfg); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	pins := &manifest.Pins{StoreID: root.StoreID, StoreVersion: root.Version, TrustAnchors: root.TrustAnchors, NodeVersions: map[string]int{}, UpdatedAt: now().UTC().Format(time.RFC3339)}
	for _, r := range root.Recovery {
		pins.RecoverySignPubkeys = append(pins.RecoverySignPubkeys, r.SignPubkey)
	}
	if err := manifest.SavePins(config.PinsPath(home), pins); err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	return nil
}

func splitOwnerRepo(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func inferOwnerRepoFromRemote(remote string) (string, string) {
	r := strings.TrimSuffix(remote, ".git")
	r = strings.TrimSuffix(r, "/")
	if i := strings.Index(r, "://"); i >= 0 {
		r = r[i+3:]
	}
	if i := strings.Index(r, "@"); i >= 0 {
		r = r[i+1:]
	}
	if i := strings.Index(r, ":"); i >= 0 {
		r = r[i+1:]
	}
	if i := strings.Index(r, "/"); i >= 0 {
		r = r[i+1:]
	}
	parts := strings.Split(r, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2], parts[len(parts)-1]
	}
	return "", ""
}

func shortHostname(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if i := strings.Index(h, "."); i > 0 {
		return h[:i]
	}
	return h
}

func pushEnrollmentRequest(ctx context.Context, a *app.App, home, remoteURL string, transport gitstore.Transport, requestID string, ct []byte, author gitstore.Author, now func() time.Time) error {
	pushDir, err := os.MkdirTemp("", "kauket-enroll-push-")
	if err != nil {
		return fmt.Errorf("kauket: temp dir: %w", err)
	}
	defer os.RemoveAll(pushDir)

	repoPath := filepath.Join(pushDir, "repo")
	lockPath := filepath.Join(pushDir, "repo.lock")

	newStore := a.NewStore
	if newStore == nil {
		newStore = gitstore.OpenOrClone
	}
	if transport == nil {
		transport = gitstore.SelectTransport(remoteURL, "")
	}
	store, err := newStore(ctx, gitstore.Config{
		RepoPath: repoPath,
		URL:      remoteURL,
		LockPath: lockPath,
		Now:      now,
	}, transport)
	if err != nil {
		return fmt.Errorf("kauket: open remote for push: %w", err)
	}
	defer store.Close()

	if err := store.Sync(ctx); err != nil {
		return fmt.Errorf("kauket: sync remote: %w", err)
	}
	if err := store.PushRequest(ctx, requestID, ct, author); err != nil {
		return fmt.Errorf("kauket: push request: %w", err)
	}
	return nil
}
