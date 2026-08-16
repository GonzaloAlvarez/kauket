package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/githubauth"
	gogithub "github.com/google/go-github/v67/github"
)

func detectGitHubOwner(ctx context.Context, a *app.App) (string, error) {
	p := &githubauth.GHCLIProvider{Shell: a.AuthShell}
	return p.ActiveLogin(ctx)
}

func githubUserLogin(ctx context.Context, hc *http.Client, token string) (string, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	client := gogithub.NewClient(hc).WithAuthToken(token)
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return "", fmt.Errorf("kauket: query github user: %w", err)
	}
	if user == nil || user.Login == nil || *user.Login == "" {
		return "", errors.New("kauket: github user has no login")
	}
	return *user.Login, nil
}
