package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/githubauth"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	"github.com/gonzaloalvarez/kauket/internal/model"
	gogithub "github.com/google/go-github/v67/github"
	"github.com/spf13/cobra"
)

const (
	defaultOwner      = "GonzaloAlvarez"
	defaultRepoName   = "kauket-store"
	defaultAuthorName = "Gonzalo Alvarez"
	defaultAuthorMail = "gonzaloab@gmail.com"
)

type initFlags struct {
	owner         string
	repo          string
	private       bool
	remote        string
	noGitHub      bool
	adminIdentity string
	yes           bool
}

func NewInit(a *app.App) *cobra.Command {
	f := &initFlags{}
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a kauket admin store",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(cmd.Context(), a, f)
		},
	}
	cmd.Flags().StringVar(&f.owner, "owner", defaultOwner, "GitHub owner for the kauket store repo")
	cmd.Flags().StringVar(&f.repo, "repo", defaultRepoName, "GitHub repo name for the kauket store")
	cmd.Flags().BoolVar(&f.private, "private", true, "Create the GitHub repo as private")
	cmd.Flags().StringVar(&f.remote, "remote", "", "Explicit Git remote URL")
	cmd.Flags().BoolVar(&f.noGitHub, "no-github", false, "Skip GitHub API; use the --remote URL as-is")
	cmd.Flags().StringVar(&f.adminIdentity, "admin-identity", "", "Path to an existing age identity to import")
	cmd.Flags().BoolVar(&f.yes, "yes", false, "Noninteractive")
	return cmd
}

func runInit(ctx context.Context, a *app.App, f *initFlags) error {
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
	if role == config.RoleClient {
		return &ExitError{
			Code: ExitUsage,
			Err:  errors.New("kauket: this machine is configured as a client; run kauket init in a fresh KAUKET_HOME or use --force-new-store (not yet implemented)"),
		}
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

	identityPath := config.AdminIdentityPath(home)
	recipient, err := ensureAdminIdentity(identityPath, f.adminIdentity)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: err}
	}

	remoteURL := strings.TrimSpace(f.remote)
	if remoteURL == "" {
		remoteURL = fmt.Sprintf("https://github.com/%s/%s.git", f.owner, f.repo)
	}

	useGitHub := !f.noGitHub && !strings.HasPrefix(remoteURL, "file://")
	if useGitHub && (strings.HasPrefix(remoteURL, "git@") || strings.HasPrefix(remoteURL, "ssh://")) {
		return &ExitError{
			Code: ExitUsage,
			Err:  errors.New("kauket: admin init does not support SSH remotes; use an HTTPS GitHub URL or pass --no-github with a local file remote"),
		}
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

	if useGitHub {
		if err := ensureGitHubRepo(ctx, a.HTTPClient, token, f.owner, f.repo, f.private); err != nil {
			return &ExitError{Code: ExitSync, Err: err}
		}
	}

	now := a.Now
	if now == nil {
		now = time.Now
	}

	storeCfg := gitstore.Config{
		RepoPath: config.RepoDir(home),
		URL:      remoteURL,
		LockPath: config.LockPath(home),
		Now:      now,
	}
	newStore := a.NewStore
	if newStore == nil {
		newStore = gitstore.OpenOrClone
	}
	store, err := newStore(ctx, storeCfg, transport)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	defer store.Close()

	repoJSONPath := filepath.Join(config.RepoDir(home), "repo.json")
	vaultPath := filepath.Join(config.RepoDir(home), "admin", "vault.age")
	existingRepoJSON, errRepoJSON := os.ReadFile(repoJSONPath)
	if errRepoJSON == nil {
		return reattachExisting(a, home, existingRepoJSON, vaultPath, identityPath, remoteURL, f.owner, f.repo, recipient)
	}
	if !errors.Is(errRepoJSON, os.ErrNotExist) {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: read repo.json: %w", errRepoJSON)}
	}

	storeID := model.NewStoreID()
	recipientID := model.NewAdminRecipientID()
	createdAt := now().UTC().Format(time.RFC3339)

	repoMeta := repoJSON{
		Schema:    1,
		StoreID:   storeID,
		CreatedAt: createdAt,
		Format: repoFormat{
			AdminVault: "kauket-admin-vault-v1",
			HostBundle: "kauket-host-bundle-v1",
			Request:    "kauket-request-v1",
			Encryption: "age-v1",
		},
		GitHub: repoGitHub{
			Owner:         f.owner,
			Repo:          f.repo,
			DefaultBranch: "main",
		},
		AdminRecipients: []repoAdminRecipient{
			{ID: recipientID, Recipient: recipient},
		},
	}
	repoBytes, err := json.MarshalIndent(repoMeta, "", "  ")
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: marshal repo.json: %w", err)}
	}
	repoBytes = append(repoBytes, '\n')
	if err := writeRepoFile(repoJSONPath, repoBytes); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}

	vault := model.Vault{
		Schema:    1,
		StoreID:   storeID,
		CreatedAt: createdAt,
		UpdatedAt: createdAt,
		Admins: []model.AdminRecipient{
			{ID: recipientID, Recipient: recipient, CreatedAt: createdAt},
		},
		Profiles: map[string]model.Profile{},
		Secrets:  map[string]model.Secret{},
		Hosts:    map[string]model.Host{},
		Requests: map[string]model.RequestRecord{},
	}
	vaultCT, err := bundle.EncodeVault(vault, agebox.X25519RecipientProvider{Strings: []string{recipient}})
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: encode vault: %w", err)}
	}
	if err := writeRepoFile(vaultPath, vaultCT); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}

	for _, dir := range []string{"bundles", "requests"} {
		keepPath := filepath.Join(config.RepoDir(home), dir, ".keep")
		if err := writeRepoFile(keepPath, []byte{}); err != nil {
			return &ExitError{Code: ExitSync, Err: err}
		}
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
			RecipientID:  recipientID,
			IdentityPath: filepath.Join("identities", "admin.txt"),
		},
		CommitAuthor: config.CommitAuthor{Name: defaultAuthorName, Email: defaultAuthorMail},
	}
	if !useGitHub {
		adminCfg.Repo.RemoteHTTPS = remoteURL
		adminCfg.Repo.RemoteSSH = ""
	}
	if err := config.SaveAdmin(home, adminCfg); err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: save admin config: %w", err)}
	}

	a.UI.Println(fmt.Sprintf("initialized kauket store %s/%s", f.owner, f.repo))
	a.UI.Println(fmt.Sprintf("admin recipient %s created", recipientID))
	return nil
}

func ensureAdminIdentity(targetPath, importPath string) (string, error) {
	if importPath != "" {
		data, err := os.ReadFile(importPath)
		if err != nil {
			return "", fmt.Errorf("kauket: read admin identity: %w", err)
		}
		ids, err := agebox.ParseIdentity(data)
		if err != nil {
			return "", err
		}
		if len(ids) != 1 {
			return "", fmt.Errorf("kauket: admin identity file must contain exactly one identity, found %d", len(ids))
		}
		x, ok := ids[0].(*age.X25519Identity)
		if !ok {
			return "", errors.New("kauket: admin identity must be an X25519 identity")
		}
		abs, err := filepath.Abs(importPath)
		if err != nil {
			return "", err
		}
		absTarget, err := filepath.Abs(targetPath)
		if err != nil {
			return "", err
		}
		if abs != absTarget {
			if err := writeIdentityFile(targetPath, []byte(x.String()+"\n")); err != nil {
				return "", err
			}
		}
		return x.Recipient().String(), nil
	}

	if _, err := os.Stat(targetPath); err == nil {
		data, readErr := os.ReadFile(targetPath)
		if readErr != nil {
			return "", fmt.Errorf("kauket: read existing admin identity: %w", readErr)
		}
		ids, parseErr := agebox.ParseIdentity(data)
		if parseErr != nil {
			return "", parseErr
		}
		if len(ids) != 1 {
			return "", fmt.Errorf("kauket: existing admin identity must contain exactly one identity, found %d", len(ids))
		}
		x, ok := ids[0].(*age.X25519Identity)
		if !ok {
			return "", errors.New("kauket: existing admin identity must be an X25519 identity")
		}
		return x.Recipient().String(), nil
	}

	id, err := agebox.GenerateIdentity()
	if err != nil {
		return "", err
	}
	if err := writeIdentityFile(targetPath, []byte(id.String()+"\n")); err != nil {
		return "", err
	}
	return id.Recipient().String(), nil
}

func writeIdentityFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("kauket: ensure identity dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("kauket: write identity: %w", err)
	}
	return nil
}

func writeRepoFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("kauket: ensure repo dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("kauket: write repo file: %w", err)
	}
	return nil
}

func ensureGitHubRepo(ctx context.Context, hc *http.Client, token, owner, repo string, private bool) error {
	if hc == nil {
		hc = http.DefaultClient
	}
	client := gogithub.NewClient(hc).WithAuthToken(token)

	_, resp, err := client.Repositories.Get(ctx, owner, repo)
	if err == nil {
		return nil
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("kauket: get repo %s/%s: %w", owner, repo, err)
	}

	name := repo
	priv := private
	autoInit := false
	newRepo := &gogithub.Repository{
		Name:     &name,
		Private:  &priv,
		AutoInit: &autoInit,
	}

	var org string
	user, _, userErr := client.Users.Get(ctx, "")
	if userErr == nil && user != nil && user.Login != nil && *user.Login != owner {
		org = owner
	}
	_, _, err = client.Repositories.Create(ctx, org, newRepo)
	if err != nil {
		return fmt.Errorf("kauket: create repo %s/%s: %w", owner, repo, err)
	}
	return nil
}

func reattachExisting(a *app.App, home string, repoJSONBytes []byte, vaultPath, identityPath, remoteURL, ownerFlag, repoFlag, recipient string) error {
	var meta repoJSON
	if err := json.Unmarshal(repoJSONBytes, &meta); err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: parse existing repo.json: %w", err)}
	}
	if meta.Schema == 0 || meta.StoreID == "" {
		return &ExitError{Code: ExitSync, Err: errors.New("kauket: repo.json present but does not look like a kauket store")}
	}
	vaultCT, err := os.ReadFile(vaultPath)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: read admin vault: %w", err)}
	}
	if _, err := bundle.DecodeVault(vaultCT, agebox.FileIdentityProvider{Path: identityPath}); err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: admin identity does not decrypt existing vault: %w", err)}
	}

	owner := meta.GitHub.Owner
	if owner == "" {
		owner = ownerFlag
	}
	repoName := meta.GitHub.Repo
	if repoName == "" {
		repoName = repoFlag
	}

	recipientID := ""
	for _, r := range meta.AdminRecipients {
		if r.Recipient == recipient {
			recipientID = r.ID
			break
		}
	}
	if recipientID == "" && len(meta.AdminRecipients) > 0 {
		recipientID = meta.AdminRecipients[0].ID
	}

	adminCfg := &config.Admin{
		Schema:  config.ConfigSchema,
		Role:    config.RoleAdmin,
		StoreID: meta.StoreID,
		Repo:    config.DefaultRepoInfo(owner, repoName),
		Admin: config.AdminInfo{
			RecipientID:  recipientID,
			IdentityPath: filepath.Join("identities", "admin.txt"),
		},
		CommitAuthor: config.CommitAuthor{Name: defaultAuthorName, Email: defaultAuthorMail},
	}
	if strings.HasPrefix(remoteURL, "file://") {
		adminCfg.Repo.RemoteHTTPS = remoteURL
		adminCfg.Repo.RemoteSSH = ""
	}
	if err := config.SaveAdmin(home, adminCfg); err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: save admin config: %w", err)}
	}

	a.UI.Println(fmt.Sprintf("initialized kauket store %s/%s", owner, repoName))
	a.UI.Println(fmt.Sprintf("admin recipient %s created", recipientID))
	return nil
}

type repoJSON struct {
	Schema          int                  `json:"schema"`
	StoreID         string               `json:"store_id"`
	CreatedAt       string               `json:"created_at"`
	Format          repoFormat           `json:"format"`
	GitHub          repoGitHub           `json:"github"`
	AdminRecipients []repoAdminRecipient `json:"admin_recipients"`
}

type repoFormat struct {
	AdminVault string `json:"admin_vault"`
	HostBundle string `json:"host_bundle"`
	Request    string `json:"request"`
	Encryption string `json:"encryption"`
}

type repoGitHub struct {
	Owner         string `json:"owner"`
	Repo          string `json:"repo"`
	DefaultBranch string `json:"default_branch"`
}

type repoAdminRecipient struct {
	ID        string `json:"id"`
	Recipient string `json:"recipient"`
}
