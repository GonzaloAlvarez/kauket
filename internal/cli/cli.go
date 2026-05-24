package cli

import "github.com/gonzaloalvarez/kauket/internal/app"

func Execute() error {
	a := app.New()
	cmd := NewRoot(a)
	return cmd.Execute()
}
