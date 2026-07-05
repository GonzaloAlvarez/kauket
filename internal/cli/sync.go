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

	var (
		remoteURL string
		transport gitstore.Transport
	)
	switch role {
	case config.RoleAdmin:
		cfg, err := config.LoadAdmin(home)
		if err != nil {
			return &ExitError{Code: ExitUsage, Err: err}
		}
		remoteURL = cfg.Repo.RemoteHTTPS
		if remoteURL == "" {
			return &ExitError{Code: ExitUsage, Err: errors.New("kauket: stored remote URL is empty")}
		}
		transport, err = buildAdminSyncTransport(ctx, a, remoteURL)
		if err != nil {
			return &ExitError{Code: ExitSync, Err: err}
		}
	case config.RoleClient:
		cfg, err := config.LoadClient(home)
		if err != nil {
			return &ExitError{Code: ExitUsage, Err: err}
		}
		// Mirror `kauket get`: prefer the SSH remote and authenticate with the
		// deploy key, so an SSH remote doesn't fall back to go-git's SSH agent.
		remoteURL = selectClientRemote(cfg)
		if remoteURL == "" {
			return &ExitError{Code: ExitUsage, Err: errors.New("kauket: stored remote URL is empty")}
		}
		transport, err = buildGetTransport(home, cfg, remoteURL)
		if err != nil {
			return &ExitError{Code: ExitSync, Err: err}
		}
	default:
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: no kauket store configured here; run 'kauket init' or 'kauket enroll' first")}
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

func buildAdminSyncTransport(ctx context.Context, a *app.App, remoteURL string) (gitstore.Transport, error) {
	if strings.HasPrefix(remoteURL, "file://") {
		return gitstore.FileURLTransport{}, nil
	}
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
