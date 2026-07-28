package cli

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/manifest"
	"github.com/gonzaloalvarez/kauket/internal/model"
)

func isNoIdentityMatch(err error) bool {
	var noMatch *age.NoIdentityMatchError
	return errors.As(err, &noMatch)
}

func translateV2ReadError(err error) error {
	if isNoIdentityMatch(err) {
		return &ExitError{Code: ExitNotGranted, Err: errors.New("kauket: not granted access to this part of the store")}
	}
	return translateManifestError(err)
}

func getV2(a *app.App, home, identityPath string, v2 *config.V2Local, f *getFlags, secretID string) error {
	vctx, err := loadV2Context(home, identityPath, v2)
	if err != nil {
		return translateV2ReadError(err)
	}
	path, key, err := splitSecretPath(secretID)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}

	res, err := manifest.WalkSpine(objectsDir(vctx.repoDir), vctx.root, vctx.pins, vctx.identity, bundle.Ed25519Verifier{}, path)
	if err != nil {
		return translateV2ReadError(err)
	}
	leaf := res.Nodes[res.SpineIDs[len(res.SpineIDs)-1]]
	ix, err := manifest.LoadIndex(objectsDir(vctx.repoDir), leaf.Body, vctx.identity)
	if err != nil {
		return translateV2ReadError(err)
	}
	entry, ok := ix.Entries[key]
	if !ok {
		return &ExitError{Code: ExitNotGranted, Err: fmt.Errorf("secret %s is not granted to this identity or does not exist", secretID)}
	}
	obj, err := manifest.LoadObject(objectsDir(vctx.repoDir), entry, vctx.identity)
	if err != nil {
		return translateV2ReadError(err)
	}
	content, err := base64.StdEncoding.DecodeString(obj.ContentBase64)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: decode secret content: %w", err)}
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != obj.SHA256 {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("%w: secret content", manifest.ErrHashMismatch)}
	}

	if err := vctx.savePins(); err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}

	if f.stdout {
		if _, err := os.Stdout.Write(content); err != nil {
			return &ExitError{Code: ExitInstall, Err: fmt.Errorf("kauket: write stdout: %w", err)}
		}
		return nil
	}

	stateID := strings.Join(append(append([]string{}, path...), key), ".")
	switch obj.Kind {
	case "", "file":
		secret := model.BundleSecret{
			Kind:          "file",
			Install:       obj.Install,
			ContentBase64: obj.ContentBase64,
			SHA256:        obj.SHA256,
		}
		return installSecret(a, home, stateID, content, secret, f)
	case "aws_profile":
		return installAWSProfileSecret(a, home, stateID, content, f)
	default:
		return &ExitError{Code: ExitInstall, Err: fmt.Errorf("kauket: secret %s has unsupported kind %q; upgrade kauket", secretID, obj.Kind)}
	}
}
