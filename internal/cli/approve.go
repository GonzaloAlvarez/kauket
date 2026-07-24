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
	"github.com/gonzaloalvarez/kauket/internal/githubauth"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	"github.com/gonzaloalvarez/kauket/internal/model"
	"github.com/spf13/cobra"
)

type approveFlags struct {
	request string
	all     bool
	yes     bool
	dryRun  bool
}

func NewApprove(a *app.App) *cobra.Command {
	f := &approveFlags{}
	cmd := &cobra.Command{
		Use:   "approve",
		Short: "Approve pending enrollment requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runApprove(cmd.Context(), a, f)
		},
	}
	cmd.Flags().StringVar(&f.request, "request", "", "approve a specific request id (rq_...)")
	cmd.Flags().BoolVar(&f.all, "all", false, "approve all pending requests")
	cmd.Flags().BoolVar(&f.yes, "yes", false, "noninteractive")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "show actions only")
	return cmd
}

type validRequest struct {
	req    model.Request
	branch string
}

func runApprove(ctx context.Context, a *app.App, f *approveFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	home, err := resolveHome(a)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: resolve home: %w", err)}
	}
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		if errors.Is(err, config.ErrNoConfig) {
			return &ExitError{Code: ExitUsage, Err: errors.New("kauket: no kauket store configured here; run 'kauket init' first")}
		}
		if errors.Is(err, config.ErrNotAdmin) {
			return &ExitError{Code: ExitUsage, Err: errors.New("kauket: kauket approve requires admin role")}
		}
		return &ExitError{Code: ExitUsage, Err: err}
	}

	remoteURL := cfg.Repo.RemoteHTTPS
	if remoteURL == "" {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: stored remote URL is empty")}
	}
	if strings.HasPrefix(remoteURL, "git@") || strings.HasPrefix(remoteURL, "ssh://") {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: approve does not support SSH remotes; use HTTPS or file remote")}
	}

	useGitHub := !strings.HasPrefix(remoteURL, "file://")

	var transport gitstore.Transport
	var token string
	if useGitHub {
		printCode := func(verifyURL, userCode string) {
			a.UI.Println(fmt.Sprintf("open %s and enter code %s", verifyURL, userCode))
		}
		tok, _, authErr := githubauth.Select(ctx, []string{"repo", "admin:public_key"}, githubauth.SelectorOptions{
			Shell:           a.AuthShell,
			ClientID:        githubauth.ClientID,
			Account:         cfg.Repo.Owner,
			PrintCode:       printCode,
			HTTPClient:      a.HTTPClient,
			AllowDeviceFlow: true,
		})
		if authErr != nil {
			return &ExitError{Code: ExitSync, Err: authErr}
		}
		token = tok
		transport = gitstore.HTTPSTokenTransport{Token: token}
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

	a.UI.Println("syncing store")
	if err := store.Sync(ctx); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}

	a.UI.Println("fetching pending requests")
	refs, err := store.FetchRequestRefs(ctx)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}

	identityPath := cfg.Admin.IdentityPath
	if !filepath.IsAbs(identityPath) {
		identityPath = filepath.Join(home, identityPath)
	}
	idProvider := agebox.FileIdentityProvider{Path: identityPath}

	vaultPath := filepath.Join(config.RepoDir(home), "admin", "vault.age")
	vaultCT, err := os.ReadFile(vaultPath)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: read admin vault: %w", err)}
	}
	vault, err := bundle.DecodeVault(vaultCT, idProvider)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: decrypt admin vault: %w", err)}
	}
	if vault.Hosts == nil {
		vault.Hosts = map[string]model.Host{}
	}
	if vault.Requests == nil {
		vault.Requests = map[string]model.RequestRecord{}
	}

	sort.Slice(refs, func(i, j int) bool {
		return refs[i].RequestID < refs[j].RequestID
	})

	var validRequests []validRequest
	for _, ref := range refs {
		shortBranch := ref.Branch
		if rec, ok := vault.Requests[ref.RequestID]; ok && rec.Status == "approved" {
			a.UI.Errorf("request %s: already approved; skipping", shortBranch)
			continue
		}
		req, decErr := bundle.DecodeRequest(ref.Content, idProvider, bundle.Ed25519Verifier{})
		if decErr != nil {
			if errors.Is(decErr, bundle.ErrInvalidSignature) || errors.Is(decErr, bundle.ErrUnsignedRequest) {
				a.UI.Errorf("request %s: invalid signature; skipping", shortBranch)
				continue
			}
			a.UI.Errorf("request %s: failed to decrypt; skipping", shortBranch)
			continue
		}
		if req.StoreID != cfg.StoreID {
			a.UI.Errorf("request %s: store_id mismatch; skipping", shortBranch)
			continue
		}
		if existing, ok := vault.Hosts[req.Host.ID]; ok && existing.AgeRecipient != req.Host.AgeRecipient {
			a.UI.Errorf("request %s: host_id %s already bound to a different recipient; refusing", shortBranch, req.Host.ID)
			continue
		}
		validRequests = append(validRequests, validRequest{req: req, branch: shortBranch})
	}

	if len(validRequests) == 0 {
		a.UI.Println("nothing to approve")
		return nil
	}

	a.UI.Println("")
	a.UI.Println("Pending requests:")
	a.UI.Println("")
	for i, v := range validRequests {
		a.UI.Println(fmt.Sprintf("%d. request %s %s-%s %s",
			i+1,
			v.req.Host.DisplayName,
			datePart(v.req.CreatedAt),
			v.req.Host.ReportedHostname,
			strings.Join(v.req.Requested.Profiles, ","),
		))
	}

	selected, err := selectRequests(a, validRequests, f)
	if err != nil {
		return err
	}
	if len(selected) == 0 {
		return nil
	}

	for _, idx := range selected {
		v := validRequests[idx]
		if f.dryRun {
			a.UI.Println(fmt.Sprintf("request %d approved (dry-run)", idx+1))
			continue
		}
		if err := approveOne(ctx, a, store, &vault, cfg, v.req, useGitHub, token, now); err != nil {
			a.UI.Errorf("request %d: %v", idx+1, err)
			continue
		}
		a.UI.Println(fmt.Sprintf("request %d approved", idx+1))
	}
	return nil
}

func datePart(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func selectRequests(a *app.App, requests []validRequest, f *approveFlags) ([]int, error) {
	if strings.TrimSpace(f.request) != "" {
		want := strings.TrimSpace(f.request)
		for i, v := range requests {
			if v.req.RequestID == want {
				return []int{i}, nil
			}
		}
		return nil, &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: request id %s not found in pending requests", want)}
	}
	if f.all {
		out := make([]int, len(requests))
		for i := range requests {
			out[i] = i
		}
		return out, nil
	}
	if f.yes {
		out := make([]int, len(requests))
		for i := range requests {
			out[i] = i
		}
		return out, nil
	}
	var out []int
	for i := range requests {
		ok, err := a.UI.Confirm(fmt.Sprintf("approve request %d?", i+1))
		if err != nil {
			return nil, &ExitError{Code: ExitUsage, Err: err}
		}
		if ok {
			out = append(out, i)
		}
	}
	return out, nil
}

func approveOne(ctx context.Context, a *app.App, store *gitstore.Store, vault *model.Vault, cfg *config.Admin, req model.Request, useGitHub bool, token string, now func() time.Time) error {
	if useGitHub {
		manager := &gitstore.DeployKeyManager{
			Owner:      cfg.Repo.Owner,
			Repo:       cfg.Repo.Name,
			Token:      token,
			HTTPClient: a.HTTPClient,
		}
		if _, err := manager.Add(ctx, req.Host.ID, req.Host.GitDeployPublicKey); err != nil {
			return fmt.Errorf("deploy key add failed: %w", err)
		}
	}

	nowStr := now().UTC().Format(time.RFC3339)
	existing := vault.Hosts[req.Host.ID]
	createdAt := existing.CreatedAt
	if createdAt == "" {
		createdAt = nowStr
	}
	vault.Hosts[req.Host.ID] = model.Host{
		DisplayName:          req.Host.DisplayName,
		ReportedHostname:     req.Host.ReportedHostname,
		AgeRecipient:         req.Host.AgeRecipient,
		DeployKeyFingerprint: req.Signature.PublicKeyFingerprint,
		GrantedProfiles:      req.Requested.Profiles,
		GrantedSecrets:       req.Requested.Secrets,
		CreatedAt:            createdAt,
		ApprovedAt:           nowStr,
	}
	vault.Requests[req.RequestID] = model.RequestRecord{
		Status:            "approved",
		HostID:            req.Host.ID,
		RequestedProfiles: req.Requested.Profiles,
		CreatedAt:         req.CreatedAt,
		ApprovedAt:        nowStr,
	}
	vault.UpdatedAt = nowStr

	generation := int(now().UnixNano())
	b, err := bundle.BuildHostBundle(*vault, req.Host.ID, now(), generation)
	if err != nil {
		return fmt.Errorf("build bundle: %w", err)
	}

	adminRecipStrings := make([]string, 0, len(vault.Admins))
	for _, ar := range vault.Admins {
		adminRecipStrings = append(adminRecipStrings, ar.Recipient)
	}
	adminRecips := agebox.X25519RecipientProvider{Strings: adminRecipStrings}
	hostRecips := agebox.X25519RecipientProvider{Strings: []string{req.Host.AgeRecipient}}

	bundleCT, err := bundle.EncodeHostBundle(b, hostRecips, adminRecips)
	if err != nil {
		return fmt.Errorf("encrypt bundle: %w", err)
	}
	newVaultCT, err := bundle.EncodeVault(*vault, adminRecips)
	if err != nil {
		return fmt.Errorf("encode vault: %w", err)
	}

	home, err := resolveHome(a)
	if err != nil {
		return err
	}
	vaultPath := filepath.Join(config.RepoDir(home), "admin", "vault.age")
	bundlePath := filepath.Join(config.RepoDir(home), "bundles", req.Host.ID+".age")
	if err := writeRepoFile(vaultPath, newVaultCT); err != nil {
		return err
	}
	if err := writeRepoFile(bundlePath, bundleCT); err != nil {
		return err
	}

	author := gitstore.Author{Name: cfg.CommitAuthor.Name, Email: cfg.CommitAuthor.Email}
	if err := store.CommitAndPush(ctx, "kauket: approve request", author); err != nil {
		if errors.Is(err, gitstore.ErrNonFastForward) {
			return fmt.Errorf("push rejected as non-fast-forward; re-run kauket approve")
		}
		return fmt.Errorf("commit and push: %w", err)
	}
	if err := store.DeleteRequestBranch(ctx, req.RequestID); err != nil {
		a.UI.Errorf("request %s: approved but failed to delete request branch: %v", req.RequestID, err)
	}
	return nil
}
