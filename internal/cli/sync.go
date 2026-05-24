package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/githubauth"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	"github.com/spf13/cobra"
)

func NewSync(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Sync the local kauket store with the remote",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSync(cmd.Context(), a)
		},
	}
}

func runSync(ctx context.Context, a *app.App) error {
	if ctx == nil {
		ctx = context.Background()
	}
	home, err := resolveHome(a)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	role, err := config.PeekRole(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}

	var remoteURL string
	switch role {
	case config.RoleAdmin:
		cfg, err := config.LoadAdmin(home)
		if err != nil {
			return &ExitError{Code: ExitUsage, Err: err}
		}
		remoteURL = cfg.Repo.RemoteHTTPS
	case config.RoleClient:
		cfg, err := config.LoadClient(home)
		if err != nil {
			return &ExitError{Code: ExitUsage, Err: err}
		}
		remoteURL = cfg.Repo.RemoteHTTPS
	default:
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: no kauket store configured here; run 'kauket init' or 'kauket enroll' first")}
	}

	if remoteURL == "" {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: stored remote URL is empty")}
	}

	transport, err := buildSyncTransport(ctx, a, remoteURL, role)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}

	newStore := a.NewStore
	if newStore == nil {
		newStore = gitstore.OpenOrClone
	}
	store, err := newStore(ctx, gitstore.Config{
		RepoPath: config.RepoDir(home),
		URL:      remoteURL,
		LockPath: config.LockPath(home),
		Now:      a.Now,
	}, transport)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	defer store.Close()

	if err := store.Sync(ctx); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	a.UI.Println("synced")
	return nil
}

func buildSyncTransport(ctx context.Context, a *app.App, remoteURL string, role config.Role) (gitstore.Transport, error) {
	if strings.HasPrefix(remoteURL, "file://") {
		return gitstore.FileURLTransport{}, nil
	}
	if role == config.RoleAdmin {
		token, _, err := githubauth.Select(ctx, []string{"repo"}, githubauth.SelectorOptions{
			Shell:           a.AuthShell,
			ClientID:        githubauth.ClientID,
			HTTPClient:      a.HTTPClient,
			AllowDeviceFlow: true,
			PrintCode: func(verifyURL, userCode string) {
				a.UI.Println(fmt.Sprintf("open %s and enter code %s", verifyURL, userCode))
			},
		})
		if err != nil {
			return nil, err
		}
		return gitstore.HTTPSTokenTransport{Token: token}, nil
	}
	return gitstore.SelectTransport(remoteURL, ""), nil
}
