package cli

import (
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/spf13/cobra"
)

func NewRoot(a *app.App) *cobra.Command {
	root := &cobra.Command{
		Use:           "kauket",
		Short:         "Direct-age, Git-backed, per-host secret bundle manager",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		NewInit(a),
		NewEnroll(a),
		NewVersion(a),
		NewStatus(a),
		NewSync(a),
		NewAdd(a),
		NewList(a),
	)
	return root
}
