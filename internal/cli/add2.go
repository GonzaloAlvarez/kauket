package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/manifest"
	"github.com/gonzaloalvarez/kauket/internal/model"
)

func runAddV2(ctx context.Context, a *app.App, home string, cfg *config.Admin, f *addFlags, secretID string, content []byte, spec model.InstallSpec, kind string) error {
	path, key, err := splitSecretPath(secretID)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if len(f.profiles) > 0 {
		a.UI.Println("warning: --profile is ignored on v2 stores; use 'kauket grant' for access control")
	}
	sum := sha256.Sum256(content)
	obj := &manifest.Object{
		Kind:          kind,
		Install:       spec,
		ContentBase64: base64.StdEncoding.EncodeToString(content),
		SHA256:        hex.EncodeToString(sum[:]),
	}
	plan, err := runV2Mutation(ctx, a, home, cfg, func(string) (manifest.Intent, error) {
		return manifest.Intent{Op: manifest.OpAdd, Path: path, Key: key, Secret: obj, Force: f.force}, nil
	})
	if err != nil {
		return err
	}
	verb := "added"
	if f.force {
		verb = "updated"
	}
	a.UI.Println(fmt.Sprintf("%s %s (%d objects updated)", verb, secretID, len(plan.Written)))
	return nil
}
