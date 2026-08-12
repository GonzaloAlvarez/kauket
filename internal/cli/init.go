package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/app"
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
	recoveryOut   string
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
	cmd.Flags().StringVar(&f.recoveryOut, "recovery-out", "", "Directory to write the offline recovery key pair (required)")
	return cmd
}

func runInit(ctx context.Context, a *app.App, f *initFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return runInitV2(ctx, a, f)
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
