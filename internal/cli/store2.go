package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/manifest"
	"github.com/gonzaloalvarez/kauket/internal/model"
	cryptossh "golang.org/x/crypto/ssh"
)

func storeRootPath(repoDir string) string {
	return filepath.Join(repoDir, "store.json")
}

func storeRootSigPath(repoDir string) string {
	return filepath.Join(repoDir, "store.json.sig")
}

func objectsDir(repoDir string) string {
	return filepath.Join(repoDir, "objects")
}

func repoIdentitiesDir(repoDir string) string {
	return filepath.Join(repoDir, "identities")
}

func isV2Store(repoDir string) bool {
	_, err := os.Stat(storeRootPath(repoDir))
	return err == nil
}

func requireV2StoreDir(repoDir string) error {
	if isV2Store(repoDir) {
		return nil
	}
	if _, err := os.Stat(repoDir); errors.Is(err, os.ErrNotExist) {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: could not reach the remote and no local store copy exists")}
	}
	return &ExitError{Code: ExitUsage, Err: errors.New("kauket: this store uses the legacy v1 schema; migrate it with the kauket v2.0.x release ('kauket migrate-store') before using this version")}
}

func splitSecretPath(arg string) ([]string, string, error) {
	var segments []string
	if strings.Contains(arg, "/") {
		segments = strings.Split(strings.Trim(arg, "/"), "/")
	} else {
		segments = strings.Split(arg, ".")
	}
	clean := make([]string, 0, len(segments))
	for _, s := range segments {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		clean = append(clean, s)
	}
	if len(clean) < 2 {
		return nil, "", fmt.Errorf("kauket: secret path %q needs at least a namespace and a key", arg)
	}
	return clean[:len(clean)-1], clean[len(clean)-1], nil
}

type v2Context struct {
	home     string
	repoDir  string
	root     manifest.StoreRoot
	pins     *manifest.Pins
	identity agebox.FileIdentityProvider
	signKey  string
	idID     string
}

func loadV2Context(home, identityPath string, v2 *config.V2Local) (*v2Context, error) {
	repoDir := config.RepoDir(home)
	doc, err := os.ReadFile(storeRootPath(repoDir))
	if err != nil {
		return nil, fmt.Errorf("kauket: read store.json: %w", err)
	}
	sig, err := os.ReadFile(storeRootSigPath(repoDir))
	if err != nil {
		return nil, fmt.Errorf("kauket: read store.json.sig: %w", err)
	}
	pins, err := manifest.LoadPins(config.PinsPath(home))
	if err != nil {
		return nil, err
	}
	var root manifest.StoreRoot
	if len(pins.TrustAnchors) == 0 && len(pins.RecoverySignPubkeys) == 0 {
		if err := json.Unmarshal(doc, &root); err != nil {
			return nil, fmt.Errorf("kauket: parse store.json: %w", err)
		}
		selfKeys := make([]string, 0, len(root.TrustAnchors)+len(root.Recovery))
		for _, a := range root.TrustAnchors {
			selfKeys = append(selfKeys, a.SignPubkey)
		}
		for _, r := range root.Recovery {
			selfKeys = append(selfKeys, r.SignPubkey)
		}
		root, _, err = manifest.VerifyStoreRoot(doc, sig, selfKeys, bundle.Ed25519Verifier{})
		if err != nil {
			return nil, err
		}
		pins.StoreID = root.StoreID
		pins.StoreVersion = root.Version
		pins.TrustAnchors = root.TrustAnchors
		for _, r := range root.Recovery {
			pins.RecoverySignPubkeys = append(pins.RecoverySignPubkeys, r.SignPubkey)
		}
	} else {
		var matchedKey string
		root, matchedKey, err = manifest.VerifyStoreRoot(doc, sig, pins.PinnedSignKeys(), bundle.Ed25519Verifier{})
		if err != nil {
			return nil, err
		}
		if pins.StoreID != "" && pins.StoreID != root.StoreID {
			return nil, fmt.Errorf("%w: pinned %s, store.json has %s", manifest.ErrStoreIDMismatch, pins.StoreID, root.StoreID)
		}
		if root.Version < pins.StoreVersion {
			return nil, fmt.Errorf("%w: store.json version %d < pinned %d", manifest.ErrStoreRollback, root.Version, pins.StoreVersion)
		}
		if !recoverySetEqual(pins.RecoverySignPubkeys, root.Recovery) && !containsString(pins.RecoverySignPubkeys, matchedKey) {
			return nil, manifest.ErrRecoveryAuthority
		}
		pins.StoreVersion = root.Version
		pins.TrustAnchors = root.TrustAnchors
		pins.RecoverySignPubkeys = nil
		for _, r := range root.Recovery {
			pins.RecoverySignPubkeys = append(pins.RecoverySignPubkeys, r.SignPubkey)
		}
	}

	if !filepath.IsAbs(identityPath) {
		identityPath = filepath.Join(home, identityPath)
	}
	ctx := &v2Context{
		home:     home,
		repoDir:  repoDir,
		root:     root,
		pins:     pins,
		identity: agebox.FileIdentityProvider{Path: identityPath},
	}
	if v2 != nil {
		ctx.idID = v2.IdentityID
		ctx.signKey = v2.SignKeyPath
		if ctx.signKey != "" && !filepath.IsAbs(ctx.signKey) {
			ctx.signKey = filepath.Join(home, ctx.signKey)
		}
	}
	return ctx, nil
}

func (c *v2Context) savePins() error {
	return manifest.SavePins(config.PinsPath(c.home), c.pins)
}

func translateManifestError(err error) error {
	switch {
	case errors.Is(err, manifest.ErrExists):
		return &ExitError{Code: ExitUsage, Err: err}
	case errors.Is(err, manifest.ErrNotFound):
		return &ExitError{Code: ExitNotGranted, Err: err}
	case errors.Is(err, manifest.ErrUntrustedSigner),
		errors.Is(err, manifest.ErrUnattestedChild),
		errors.Is(err, manifest.ErrRollback),
		errors.Is(err, manifest.ErrHashMismatch),
		errors.Is(err, manifest.ErrStoreIDMismatch),
		errors.Is(err, manifest.ErrUnsignedManifest):
		return &ExitError{Code: ExitCrypto, Err: err}
	default:
		return &ExitError{Code: ExitCrypto, Err: err}
	}
}

func ensureSignKey(path string) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		signer, parseErr := cryptossh.ParsePrivateKey(data)
		if parseErr != nil {
			return "", fmt.Errorf("kauket: parse existing sign key: %w", parseErr)
		}
		return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(signer.PublicKey()))), nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("kauket: generate sign key: %w", err)
	}
	block, err := cryptossh.MarshalPrivateKey(priv, "kauket-sign")
	if err != nil {
		return "", fmt.Errorf("kauket: marshal sign key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("kauket: ensure sign key dir: %w", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return "", fmt.Errorf("kauket: write sign key: %w", err)
	}
	sshPub, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("kauket: build sign public key: %w", err)
	}
	return strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(sshPub))), nil
}

func writeRecoveryPair(outDir string) (ageRecipient, signPub string, err error) {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", "", fmt.Errorf("kauket: create recovery dir: %w", err)
	}
	id, err := agebox.GenerateIdentity()
	if err != nil {
		return "", "", err
	}
	agePath := filepath.Join(outDir, "recovery-age.txt")
	if err := os.WriteFile(agePath, []byte(id.String()+"\n"), 0o600); err != nil {
		return "", "", fmt.Errorf("kauket: write recovery age identity: %w", err)
	}
	signPath := filepath.Join(outDir, "recovery-sign.key")
	signPub, err = ensureSignKey(signPath)
	if err != nil {
		return "", "", err
	}
	return id.Recipient().String(), signPub, nil
}

func writeIdentityRecord(repoDir string, rec manifest.IdentityRecord) error {
	if err := model.ValidateIdentityID(rec.ID); err != nil {
		return fmt.Errorf("kauket: %w", err)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("kauket: marshal identity record: %w", err)
	}
	data = append(data, '\n')
	return writeRepoFile(filepath.Join(repoIdentitiesDir(repoDir), rec.ID+".json"), data)
}

func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func recoverySetEqual(pinned []string, cur []manifest.RecoveryKey) bool {
	if len(pinned) != len(cur) {
		return false
	}
	for _, r := range cur {
		if !containsString(pinned, r.SignPubkey) {
			return false
		}
	}
	return true
}

func rewriteStoreRoot(repoDir, signKeyPath string, mutate func(*manifest.StoreRoot) error) error {
	doc, err := os.ReadFile(storeRootPath(repoDir))
	if err != nil {
		return fmt.Errorf("kauket: read store.json: %w", err)
	}
	var root manifest.StoreRoot
	if err := json.Unmarshal(doc, &root); err != nil {
		return fmt.Errorf("kauket: parse store.json: %w", err)
	}
	if err := mutate(&root); err != nil {
		return err
	}
	if root.Sealed() {
		root.Version++
	}
	newDoc, newSig, err := manifest.SignStoreRoot(root, bundle.Ed25519FileSigner{Path: signKeyPath})
	if err != nil {
		return err
	}
	if err := os.WriteFile(storeRootPath(repoDir), newDoc, 0o600); err != nil {
		return fmt.Errorf("kauket: write store.json: %w", err)
	}
	if err := os.WriteFile(storeRootSigPath(repoDir), newSig, 0o600); err != nil {
		return fmt.Errorf("kauket: write store.json.sig: %w", err)
	}
	return nil
}

func appendStoreAnchor(repoDir, signKeyPath string, rec manifest.IdentityRecord) error {
	return rewriteStoreRoot(repoDir, signKeyPath, func(root *manifest.StoreRoot) error {
		for _, t := range root.TrustAnchors {
			if t.IID == rec.ID {
				return nil
			}
		}
		root.TrustAnchors = append(root.TrustAnchors, manifest.TrustAnchor{
			IID: rec.ID, SignPubkey: rec.SSHEd25519Pubkey, AgeRecipient: rec.AgeRecipient,
		})
		return nil
	})
}

func removeStoreAnchor(repoDir, signKeyPath, identityID string) error {
	return rewriteStoreRoot(repoDir, signKeyPath, func(root *manifest.StoreRoot) error {
		kept := root.TrustAnchors[:0]
		for _, t := range root.TrustAnchors {
			if t.IID != identityID {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			return errors.New("kauket: refusing to remove the last trust anchor")
		}
		root.TrustAnchors = kept
		return nil
	})
}

func ensureHostIdentity(path string) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		ids, parseErr := agebox.ParseIdentity(data)
		if parseErr != nil {
			return "", parseErr
		}
		if len(ids) != 1 {
			return "", fmt.Errorf("kauket: existing host identity must contain exactly one identity, found %d", len(ids))
		}
		x, ok := ids[0].(*age.X25519Identity)
		if !ok {
			return "", errors.New("kauket: existing host identity must be an X25519 identity")
		}
		return x.Recipient().String(), nil
	}
	id, err := agebox.GenerateIdentity()
	if err != nil {
		return "", err
	}
	if err := writeIdentityFile(path, []byte(id.String()+"\n")); err != nil {
		return "", err
	}
	return id.Recipient().String(), nil
}

func ensureDeployKey(privPath, pubPath string) (string, error) {
	if data, err := os.ReadFile(privPath); err == nil {
		signer, parseErr := cryptossh.ParsePrivateKey(data)
		if parseErr != nil {
			return "", fmt.Errorf("kauket: parse existing deploy key: %w", parseErr)
		}
		if signer.PublicKey().Type() != cryptossh.KeyAlgoED25519 {
			return "", errors.New("kauket: existing deploy key is not ed25519")
		}
		pub := strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(signer.PublicKey())))
		if _, statErr := os.Stat(pubPath); statErr != nil {
			if err := writeFileMode(pubPath, []byte(pub+"\n"), 0o644); err != nil {
				return "", err
			}
		}
		return pub, nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("kauket: generate deploy key: %w", err)
	}
	block, err := cryptossh.MarshalPrivateKey(priv, "kauket-deploy")
	if err != nil {
		return "", fmt.Errorf("kauket: marshal deploy key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := writeFileMode(privPath, pemBytes, 0o600); err != nil {
		return "", err
	}
	sshPub, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("kauket: build public key: %w", err)
	}
	pubAuthorized := strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(sshPub)))
	if err := writeFileMode(pubPath, []byte(pubAuthorized+"\n"), 0o644); err != nil {
		return "", err
	}
	return pubAuthorized, nil
}

func writeFileMode(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("kauket: ensure dir: %w", err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("kauket: write %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("kauket: chmod %s: %w", path, err)
	}
	return nil
}
