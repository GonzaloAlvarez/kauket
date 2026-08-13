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
	"github.com/spf13/cobra"
)

type approveFlags struct {
	request       string
	all           bool
	yes           bool
	dryRun        bool
	enrollUnknown bool
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
	cmd.Flags().BoolVar(&f.enrollUnknown, "enroll-unknown", false, "noninteractively enroll not-yet-known identities (adds their read-only deploy key)")
	return cmd
}

func runApprove(ctx context.Context, a *app.App, f *approveFlags) error {
	if ctx == nil {
		ctx = context.Background()
	}
	home, err := requireRoleHome(a, config.RoleAdmin, "kauket approve")
	if err != nil {
		return err
	}
	cfg, err := config.LoadAdmin(home)
	if err != nil {
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

	if err := requireV2StoreDir(config.RepoDir(home)); err != nil {
		return err
	}
	return runApproveV2(ctx, a, home, cfg, f, store, useGitHub, token, now)
}

func datePart(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}
