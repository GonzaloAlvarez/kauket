package cli

import (
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
)

func resolveHome(a *app.App) (string, error) {
	if a.Home != "" {
		return a.Home, nil
	}
	return config.Home()
}
