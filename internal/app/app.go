package app

import (
	"context"
	"net/http"
	"time"

	"github.com/gonzaloalvarez/kauket/internal/githubauth"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	"github.com/gonzaloalvarez/kauket/internal/ui"
)

type App struct {
	UI         ui.UI
	Home       string
	Now        func() time.Time
	AuthShell  githubauth.Shell
	HTTPClient *http.Client
	NewStore   func(ctx context.Context, cfg gitstore.Config, t gitstore.Transport) (*gitstore.Store, error)
}

func New() *App {
	return &App{
		UI:         ui.NewTerminal(),
		Now:        time.Now,
		AuthShell:  githubauth.SystemShell{},
		HTTPClient: http.DefaultClient,
		NewStore:   gitstore.OpenOrClone,
	}
}
