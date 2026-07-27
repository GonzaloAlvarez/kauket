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
	var roleFlag string
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync the local kauket store with the remote",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSync(cmd.Context(), a, roleFlag)
		},
	}
	cmd.Flags().StringVar(&roleFlag, "role", "", "limit to one role (admin|client)")
	return cmd
}

func runSync(ctx context.Context, a *app.App, roleFlag string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	targets, err := resolveTargetRoles(a, roleFlag)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: no kauket store configured here; run 'kauket init' or 'kauket enroll' first")}
	}
	dual := len(targets) > 1
	for _, t := range targets {
		if t.role == config.RoleAdmin {
			err = syncAdmin(ctx, a, t.home)
		} else {
			err = syncClient(ctx, a, t.home)
		}
		if err != nil {
			return err
		}
		if dual {
			a.UI.Println(fmt.Sprintf("synced %s", t.role))
		} else {
			a.UI.Println("synced")
		}
	}
	return nil
}

func syncAdmin(ctx context.Context, a *app.App, home string) error {
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	remoteURL := cfg.Repo.RemoteHTTPS
	if remoteURL == "" {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: stored remote URL is empty")}
	}
	transport, err := buildAdminSyncTransport(ctx, a, remoteURL, cfg.Repo.Owner)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	return syncOne(ctx, a, home, remoteURL, transport)
}

func syncClient(ctx context.Context, a *app.App, home string) error {
	cfg, err := config.LoadClient(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	remoteURL := selectClientRemote(cfg)
	if remoteURL == "" {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: stored remote URL is empty")}
	}
	transport, err := buildGetTransport(home, cfg, remoteURL)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	return syncOne(ctx, a, home, remoteURL, transport)
}

func syncOne(ctx context.Context, a *app.App, home, remoteURL string, transport gitstore.Transport) error {
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
	return nil
}

func buildAdminSyncTransport(ctx context.Context, a *app.App, remoteURL, account string) (gitstore.Transport, error) {
	if strings.HasPrefix(remoteURL, "file://") {
		return gitstore.FileURLTransport{}, nil
	}
	token, _, err := githubauth.Select(ctx, []string{"repo"}, githubauth.SelectorOptions{
		Shell:           a.AuthShell,
		ClientID:        githubauth.ClientID,
		Account:         account,
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
