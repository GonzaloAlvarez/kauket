package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/awsconfig"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	"github.com/gonzaloalvarez/kauket/internal/model"
	"github.com/spf13/cobra"
)

const defaultMaxSecretSize = 4 * 1024 * 1024

type addFlags struct {
	dest          string
	mode          string
	directoryMode string
	profiles      []string
	awsProfile    string
	force         bool
	maxSize       int
}

func NewAdd(a *app.App) *cobra.Command {
	f := &addFlags{}
	cmd := &cobra.Command{
		Use:   "add <secret-id> <source-file> | add --aws-profile <name>",
		Short: "Add or update a secret in the admin vault",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			secretID := ""
			sourcePath := ""
			if len(args) > 0 {
				secretID = args[0]
			}
			if len(args) > 1 {
				sourcePath = args[1]
			}
			return runAdd(cmd.Context(), a, f, secretID, sourcePath)
		},
	}
	cmd.Flags().StringVar(&f.dest, "dest", "", "destination path on target machines")
	cmd.Flags().StringVar(&f.mode, "mode", "", "file mode (default inferred)")
	cmd.Flags().StringVar(&f.directoryMode, "directory-mode", "", "parent directory mode (default inferred)")
	cmd.Flags().StringArrayVar(&f.profiles, "profile", nil, "repeatable; assigns the secret to a profile (default inferred from secret-id prefix)")
	cmd.Flags().StringVar(&f.awsProfile, "aws-profile", "", "capture an AWS profile from ~/.aws into secret aws.profile.<name>")
	cmd.Flags().BoolVar(&f.force, "force", false, "replace existing secret")
	cmd.Flags().IntVar(&f.maxSize, "max-size", 0, "override max-size cap (bytes); 0 = use default 4MiB")
	return cmd
}

func runAdd(ctx context.Context, a *app.App, f *addFlags, secretID, sourcePath string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	home, err := requireRoleHome(a, config.RoleAdmin, "kauket add")
	if err != nil {
		return err
	}

	cfg, err := config.LoadAdmin(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}

	limit := defaultMaxSecretSize
	if f.maxSize > 0 {
		limit = f.maxSize
	}

	kind := "file"
	var content []byte
	var spec model.InstallSpec
	if f.awsProfile != "" {
		kind = "aws_profile"
		if secretID != "" || sourcePath != "" {
			return &ExitError{Code: ExitUsage, Err: errors.New("kauket: --aws-profile takes no positional arguments")}
		}
		if strings.TrimSpace(f.dest) != "" || strings.TrimSpace(f.mode) != "" || strings.TrimSpace(f.directoryMode) != "" {
			return &ExitError{Code: ExitUsage, Err: errors.New("kauket: --dest, --mode, and --directory-mode cannot be used with --aws-profile")}
		}
		secretID = "aws.profile." + f.awsProfile
		if err := model.ValidateSecretID(secretID); err != nil {
			return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: aws profile name %q cannot be encoded as a secret id: %w", f.awsProfile, err)}
		}
		configText, credsText, configPath, credsPath, err := awsconfig.ReadFiles()
		if err != nil {
			return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: %w", err)}
		}
		captured, err := awsconfig.CaptureProfile(f.awsProfile, configText, credsText, configPath, credsPath)
		if err != nil {
			return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: %w", err)}
		}
		for _, line := range captured.Captured {
			a.UI.Println(line)
		}
		for _, w := range captured.Warnings {
			a.UI.Println("warning: " + w)
		}
		content, err = captured.Envelope.Marshal()
		if err != nil {
			return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: encode aws profile: %w", err)}
		}
		if len(content) > limit {
			return &ExitError{Code: ExitUsage, Err: errors.New("kauket: source exceeds max size; use --max-size to raise")}
		}
	} else {
		if secretID == "" || sourcePath == "" {
			return &ExitError{Code: ExitUsage, Err: errors.New("kauket: add requires <secret-id> <source-file> arguments, or --aws-profile <name>")}
		}
		if err := model.ValidateSecretID(secretID); err != nil {
			return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: %w", err)}
		}

		info, err := os.Stat(sourcePath)
		if err != nil {
			return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: stat source: %w", err)}
		}
		if info.IsDir() {
			return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: source %q is a directory", sourcePath)}
		}
		if info.Size() > int64(limit) {
			return &ExitError{Code: ExitUsage, Err: errors.New("kauket: source exceeds max size; use --max-size to raise")}
		}
		content, err = os.ReadFile(sourcePath)
		if err != nil {
			return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: read source: %w", err)}
		}
		if len(content) > limit {
			return &ExitError{Code: ExitUsage, Err: errors.New("kauket: source exceeds max size; use --max-size to raise")}
		}

		var inferErr error
		spec, inferErr = model.InferInstallSpec(secretID, sourcePath)
		if inferErr != nil && !errors.Is(inferErr, model.ErrNoDestRule) {
			return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: infer install spec: %w", inferErr)}
		}
		if errors.Is(inferErr, model.ErrNoDestRule) && strings.TrimSpace(f.dest) == "" {
			return &ExitError{Code: ExitUsage, Err: fmt.Errorf("no destination rule for secret %q; pass --dest", secretID)}
		}
		if strings.TrimSpace(f.dest) != "" {
			spec.Destination = f.dest
		}
		if strings.TrimSpace(f.mode) != "" {
			spec.Mode = f.mode
		}
		if strings.TrimSpace(f.directoryMode) != "" {
			spec.DirectoryMode = f.directoryMode
		}
		if spec.Mode == "" {
			spec.Mode = "0600"
		}
		if spec.DirectoryMode == "" {
			spec.DirectoryMode = "0700"
		}
	}

	sum := sha256.Sum256(content)
	sha := hex.EncodeToString(sum[:])
	contentB64 := base64.StdEncoding.EncodeToString(content)

	var profileList []string
	if len(f.profiles) > 0 {
		profileList = append(profileList, f.profiles...)
	} else if inferred := model.InferProfile(secretID); inferred != "" {
		profileList = []string{inferred}
	}

	transport, err := buildAdminSyncTransport(ctx, a, cfg.Repo.RemoteHTTPS, cfg.Repo.Owner)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	newStore := a.NewStore
	if newStore == nil {
		newStore = gitstore.OpenOrClone
	}
	now := a.Now
	if now == nil {
		now = time.Now
	}
	store, err := newStore(ctx, gitstore.Config{
		RepoPath: config.RepoDir(home),
		URL:      cfg.Repo.RemoteHTTPS,
		LockPath: config.LockPath(home),
		Now:      now,
	}, transport)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	defer store.Close()

	if err := store.Sync(ctx); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}

	identityPath := cfg.Admin.IdentityPath
	if !filepath.IsAbs(identityPath) {
		identityPath = filepath.Join(home, identityPath)
	}
	vaultPath := filepath.Join(config.RepoDir(home), "admin", "vault.age")
	vaultCT, err := os.ReadFile(vaultPath)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: read admin vault: %w", err)}
	}
	vault, err := bundle.DecodeVault(vaultCT, agebox.FileIdentityProvider{Path: identityPath})
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: decrypt admin vault: %w", err)}
	}
	if vault.Secrets == nil {
		vault.Secrets = map[string]model.Secret{}
	}
	if vault.Hosts == nil {
		vault.Hosts = map[string]model.Host{}
	}

	nowStr := now().UTC().Format(time.RFC3339)
	existing, present := vault.Secrets[secretID]
	if present && !f.force {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: secret already exists; use --force to replace")}
	}
	updated := model.Secret{
		SecretObjectID: existing.SecretObjectID,
		Kind:           kind,
		Profiles:       profileList,
		Install:        spec,
		ContentBase64:  contentB64,
		SHA256:         sha,
		CreatedAt:      existing.CreatedAt,
		UpdatedAt:      nowStr,
	}
	if updated.SecretObjectID == "" {
		updated.SecretObjectID = model.NewSecretObjectID()
	}
	if updated.CreatedAt == "" {
		updated.CreatedAt = nowStr
	}
	vault.Secrets[secretID] = updated
	vault.UpdatedAt = nowStr

	affected := affectedHosts(vault, secretID, profileList)
	bundleCTs := make(map[string][]byte, len(affected))
	adminRecipStrings := make([]string, 0, len(vault.Admins))
	for _, ar := range vault.Admins {
		adminRecipStrings = append(adminRecipStrings, ar.Recipient)
	}
	adminRecips := agebox.X25519RecipientProvider{Strings: adminRecipStrings}
	generation := now().UnixNano()
	for _, hostID := range affected {
		host := vault.Hosts[hostID]
		b, err := bundle.BuildHostBundle(vault, hostID, now(), int(generation))
		if err != nil {
			return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: build bundle for %s: %w", hostID, err)}
		}
		hostRecip := agebox.X25519RecipientProvider{Strings: []string{host.AgeRecipient}}
		ct, err := bundle.EncodeHostBundle(b, hostRecip, adminRecips)
		if err != nil {
			return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: encrypt bundle for %s: %w", hostID, err)}
		}
		bundleCTs[hostID] = ct
	}

	newVaultCT, err := bundle.EncodeVault(vault, adminRecips)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: encode vault: %w", err)}
	}
	if err := writeRepoFile(vaultPath, newVaultCT); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	for hostID, ct := range bundleCTs {
		path := filepath.Join(config.RepoDir(home), "bundles", hostID+".age")
		if err := writeRepoFile(path, ct); err != nil {
			return &ExitError{Code: ExitSync, Err: err}
		}
	}

	author := gitstore.Author{Name: cfg.CommitAuthor.Name, Email: cfg.CommitAuthor.Email}
	if err := store.CommitAndPush(ctx, "kauket: update vault", author); err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: commit and push: %w", err)}
	}

	if present {
		a.UI.Println(fmt.Sprintf("updated %s", secretID))
	} else {
		a.UI.Println(fmt.Sprintf("added %s", secretID))
	}
	a.UI.Println(fmt.Sprintf("updated %d host bundles", len(affected)))
	return nil
}

func affectedHosts(v model.Vault, secretID string, profiles []string) []string {
	profileSet := make(map[string]struct{}, len(profiles))
	for _, p := range profiles {
		profileSet[p] = struct{}{}
	}
	out := make([]string, 0, len(v.Hosts))
	for id, host := range v.Hosts {
		match := false
		for _, gs := range host.GrantedSecrets {
			if gs == secretID {
				match = true
				break
			}
		}
		if !match {
			for _, gp := range host.GrantedProfiles {
				if _, ok := profileSet[gp]; ok {
					match = true
					break
				}
			}
		}
		if match {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
