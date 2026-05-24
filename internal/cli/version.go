package cli

import (
	"fmt"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/buildflags"
	"github.com/spf13/cobra"
)

func NewVersion(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the kauket version",
		RunE: func(cmd *cobra.Command, args []string) error {
			a.UI.Println(fmt.Sprintf("kauket %s (commit %s, built %s)", buildflags.Version, buildflags.Commit, buildflags.Date))
			return nil
		},
	}
}
