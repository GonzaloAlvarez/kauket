package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"encoding/pem"

	"filippo.io/age"
	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/githubauth"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	"github.com/gonzaloalvarez/kauket/internal/model"
	"github.com/spf13/cobra"
	cryptossh "golang.org/x/crypto/ssh"
)

type enrollFlags struct {
	requests []string
	name     string
	repo     string
	remote   string
	offline  bool
	yes      bool
}

func NewEnroll(a *app.App) *cobra.Command {
	f := &enrollFlags{}
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this machine to a kauket store and request access",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnroll(cmd.Context(), a, f)
		},
	}
	cmd.Flags().StringArrayVar(&f.requests, "request", nil, "repeatable; profile to request (e.g. ssh)")
	cmd.Flags().StringVar(&f.name, "name", "", "host display name; defaults to short hostname")
	cmd.Flags().StringVar(&f.repo, "repo", "", "owner/repo override")
	cmd.Flags().StringVar(&f.remote, "remote", "", "explicit Git remote URL")
	cmd.Flags().BoolVar(&f.offline, "offline", false, "print request code instead of pushing to remote")
	cmd.Flags().BoolVar(&f.yes, "yes", false, "noninteractive")
	return cmd
}

func runEnroll(ctx context.Context, a *app.App, f *enrollFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	home, err := resolveHome(a)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: resolve home: %w", err)}
	}

	role, err := config.PeekRole(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if role == config.RoleAdmin {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: this machine is configured as admin; enroll is for new client machines")}
	}
	if role == config.RoleClient {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: already enrolled; remove KAUKET_HOME to re-enroll")}
	}

	if len(f.requests) == 0 {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: at least one --request profile is required")}
	}
	profiles := make([]string, 0, len(f.requests))
	for _, p := range f.requests {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		profiles = append(profiles, p)
	}
	if len(profiles) == 0 {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: at least one --request profile is required")}
	}

	owner, repoName, remoteURL, err := resolveEnrollRemote(f)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
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

	hostIdentityPath := config.HostIdentityPath(home)
	hostRecipient, err := ensureHostIdentity(hostIdentityPath)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}

	deployKeyPath := config.DeployKeyPath(home)
	deployKeyPubPath := config.DeployKeyPubPath(home)
	deployPub, err := ensureDeployKey(deployKeyPath, deployKeyPubPath)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}

	useGitHub := !strings.HasPrefix(remoteURL, "file://")
	if useGitHub && (strings.HasPrefix(remoteURL, "git@") || strings.HasPrefix(remoteURL, "ssh://")) {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: enroll does not support SSH remotes; use an HTTPS GitHub URL or a file URL")}
	}
	if f.offline && useGitHub {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: --offline requires a local remote so repo.json can be read without network access")}
	}

	var transport gitstore.Transport
	var token string
	if f.offline {
		transport = gitstore.FileURLTransport{}
	} else if useGitHub {
		printCode := func(verifyURL, userCode string) {
			a.UI.Println(fmt.Sprintf("open %s and enter code %s", verifyURL, userCode))
		}
		tok, _, authErr := githubauth.Select(ctx, []string{"repo"}, githubauth.SelectorOptions{
			Shell:           a.AuthShell,
			ClientID:        githubauth.ClientID,
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

	repoMeta, err := fetchRepoJSON(ctx, a, remoteURL, transport, now)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}

	adminRecipients := make([]string, 0, len(repoMeta.AdminRecipients))
	for _, r := range repoMeta.AdminRecipients {
		if r.Recipient == "" {
			continue
		}
		adminRecipients = append(adminRecipients, r.Recipient)
	}
	if len(adminRecipients) == 0 {
		return &ExitError{Code: ExitSync, Err: errors.New("kauket: repo.json has no admin_recipients")}
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
		StoreID:   repoMeta.StoreID,
		RequestID: requestID,
		CreatedAt: now().UTC().Format(time.RFC3339),
		Host: model.RequestHost{
			ID:                 hostID,
			DisplayName:        displayName,
			ReportedHostname:   osHostname,
			OS:                 runtime.GOOS,
			Arch:               runtime.GOARCH,
			AgeRecipient:       hostRecipient,
			GitDeployPublicKey: deployPub,
		},
		Requested: model.RequestedItems{
			Profiles: profiles,
			Secrets:  nil,
		},
	}

	signer := bundle.Ed25519FileSigner{Path: deployKeyPath}
	ct, err := bundle.EncodeRequest(req, signer, agebox.X25519RecipientProvider{Strings: adminRecipients})
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: encode request: %w", err)}
	}

	syntheticAuthor := gitstore.Author{
		Name:  "kauket-" + hostID,
		Email: "kauket@" + hostID + ".local",
	}

	if f.offline {
		encoded := base64.StdEncoding.EncodeToString(ct)
		a.UI.Println("created offline enrollment request")
		a.UI.Println("")
		a.UI.Println(fmt.Sprintf("kauket approve --request-code %s", encoded))
	} else {
		if err := pushEnrollmentRequest(ctx, a, home, remoteURL, transport, requestID, ct, syntheticAuthor, now); err != nil {
			return &ExitError{Code: ExitSync, Err: err}
		}
		a.UI.Println(fmt.Sprintf("created enrollment request %s", requestID))
		a.UI.Println(fmt.Sprintf("requested profiles: %s", strings.Join(profiles, ", ")))
		a.UI.Println("waiting for approval")
	}

	effectiveOwner := owner
	effectiveRepo := repoName
	if strings.TrimSpace(f.repo) == "" {
		if repoMeta.GitHub.Owner != "" {
			effectiveOwner = repoMeta.GitHub.Owner
		}
		if repoMeta.GitHub.Repo != "" {
			effectiveRepo = repoMeta.GitHub.Repo
		}
	}
	clientCfg := &config.Client{
		Schema:  config.ConfigSchema,
		Role:    config.RoleClient,
		StoreID: repoMeta.StoreID,
		Host: config.HostInfo{
			ID:            hostID,
			DisplayName:   displayName,
			IdentityPath:  filepath.Join("identities", "host.txt"),
			DeployKeyPath: filepath.Join("git", "deploy_key"),
		},
		Repo:         config.DefaultRepoInfo(effectiveOwner, effectiveRepo),
		CommitAuthor: config.CommitAuthor{Name: syntheticAuthor.Name, Email: syntheticAuthor.Email},
	}
	if !useGitHub {
		clientCfg.Repo.RemoteHTTPS = remoteURL
		clientCfg.Repo.RemoteSSH = ""
	}
	if err := config.SaveClient(home, clientCfg); err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: save client config: %w", err)}
	}
	return nil
}

func resolveEnrollRemote(f *enrollFlags) (string, string, string, error) {
	remoteFlag := strings.TrimSpace(f.remote)
	if remoteFlag != "" {
		owner, repoName := splitOwnerRepo(f.repo)
		if owner == "" || repoName == "" {
			owner, repoName = inferOwnerRepoFromRemote(remoteFlag)
		}
		if owner == "" {
			owner = defaultOwner
		}
		if repoName == "" {
			repoName = defaultRepoName
		}
		return owner, repoName, remoteFlag, nil
	}
	src := strings.TrimSpace(f.repo)
	if src == "" {
		src = strings.TrimSpace(config.EnvRepo())
	}
	if src == "" {
		return "", "", "", errors.New("kauket: --remote, --repo, or KAUKET_REPO is required")
	}
	owner, repoName := splitOwnerRepo(src)
	if owner == "" || repoName == "" {
		return "", "", "", fmt.Errorf("kauket: invalid owner/repo %q; expected owner/repo", src)
	}
	return owner, repoName, fmt.Sprintf("https://github.com/%s/%s.git", owner, repoName), nil
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

func ensureHostIdentity(path string) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		ids, parseErr := agebox.ParseIdentity(data)
		if parseErr != nil {
			return "", parseErr
		}
		if len(ids) != 1 {
			return "", fmt.Errorf("kauket: existing host identity must contain exactly one identity, found %d", len(ids))
		}
		x, ok := ids[0].(*age.X25519Identity)
		if !ok {
			return "", errors.New("kauket: existing host identity must be an X25519 identity")
		}
		return x.Recipient().String(), nil
	}
	id, err := agebox.GenerateIdentity()
	if err != nil {
		return "", err
	}
	if err := writeIdentityFile(path, []byte(id.String()+"\n")); err != nil {
		return "", err
	}
	return id.Recipient().String(), nil
}

func ensureDeployKey(privPath, pubPath string) (string, error) {
	if data, err := os.ReadFile(privPath); err == nil {
		signer, parseErr := cryptossh.ParsePrivateKey(data)
		if parseErr != nil {
			return "", fmt.Errorf("kauket: parse existing deploy key: %w", parseErr)
		}
		if signer.PublicKey().Type() != cryptossh.KeyAlgoED25519 {
			return "", errors.New("kauket: existing deploy key is not ed25519")
		}
		pub := strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(signer.PublicKey())))
		if _, statErr := os.Stat(pubPath); statErr != nil {
			if err := writeFileMode(pubPath, []byte(pub+"\n"), 0o644); err != nil {
				return "", err
			}
		}
		return pub, nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("kauket: generate deploy key: %w", err)
	}
	block, err := cryptossh.MarshalPrivateKey(priv, "kauket-deploy")
	if err != nil {
		return "", fmt.Errorf("kauket: marshal deploy key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := writeFileMode(privPath, pemBytes, 0o600); err != nil {
		return "", err
	}
	sshPub, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("kauket: build public key: %w", err)
	}
	pubAuthorized := strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(sshPub)))
	if err := writeFileMode(pubPath, []byte(pubAuthorized+"\n"), 0o644); err != nil {
		return "", err
	}
	return pubAuthorized, nil
}

func writeFileMode(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("kauket: ensure dir: %w", err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("kauket: write %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("kauket: chmod %s: %w", path, err)
	}
	return nil
}

func fetchRepoJSON(ctx context.Context, a *app.App, remoteURL string, transport gitstore.Transport, now func() time.Time) (*repoJSON, error) {
	tempDir, err := os.MkdirTemp("", "kauket-enroll-fetch-")
	if err != nil {
		return nil, fmt.Errorf("kauket: temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	repoPath := filepath.Join(tempDir, "repo")
	lockPath := filepath.Join(tempDir, "repo.lock")

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
		return nil, fmt.Errorf("kauket: open remote for fetch: %w", err)
	}
	defer store.Close()

	if err := store.Sync(ctx); err != nil {
		return nil, fmt.Errorf("kauket: sync remote: %w", err)
	}

	repoJSONPath := filepath.Join(repoPath, "repo.json")
	data, err := os.ReadFile(repoJSONPath)
	if err != nil {
		return nil, fmt.Errorf("kauket: read repo.json: %w", err)
	}
	var meta repoJSON
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("kauket: parse repo.json: %w", err)
	}
	if meta.Schema == 0 || meta.StoreID == "" {
		return nil, errors.New("kauket: repo.json present but does not look like a kauket store")
	}
	return &meta, nil
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
