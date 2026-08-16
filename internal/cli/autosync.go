package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/githubauth"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
)

const readSyncTimeout = 20 * time.Second

func syncForRead(ctx context.Context, a *app.App, role config.Role, home string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	sctx, cancel := context.WithTimeout(ctx, readSyncTimeout)
	defer cancel()
	var err error
	if role == config.RoleAdmin {
		err = syncAdminWith(sctx, a, home, false)
	} else {
		err = syncClient(sctx, a, home)
	}
	if err == nil {
		return nil
	}
	if isV2Store(config.RepoDir(home)) {
		a.UI.Errorf("kauket: sync failed (%v); using local store copy", err)
		return nil
	}
	return err
}

func syncAdminWith(ctx context.Context, a *app.App, home string, allowDeviceFlow bool) error {
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	remoteURL := cfg.Repo.RemoteHTTPS
	if remoteURL == "" {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: stored remote URL is empty")}
	}
	transport, err := buildAdminTransport(ctx, a, remoteURL, cfg.Repo.Owner, allowDeviceFlow)
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
	return buildAdminTransport(ctx, a, remoteURL, account, true)
}

func buildAdminTransport(ctx context.Context, a *app.App, remoteURL, account string, allowDeviceFlow bool) (gitstore.Transport, error) {
	if strings.HasPrefix(remoteURL, "file://") {
		return gitstore.FileURLTransport{}, nil
	}
	token, _, err := githubauth.Select(ctx, []string{"repo"}, githubauth.SelectorOptions{
		Shell:           a.AuthShell,
		ClientID:        githubauth.ClientID,
		Account:         account,
		HTTPClient:      a.HTTPClient,
		AllowDeviceFlow: allowDeviceFlow,
		PrintCode: func(verifyURL, userCode string) {
			a.UI.Println(fmt.Sprintf("open %s and enter code %s", verifyURL, userCode))
		},
	})
	if err != nil {
		return nil, err
	}
	return gitstore.HTTPSTokenTransport{Token: token}, nil
}
