package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	"github.com/gonzaloalvarez/kauket/internal/install"
	"github.com/gonzaloalvarez/kauket/internal/model"
	"github.com/spf13/cobra"
)

type getFlags struct {
	stdout  bool
	force   bool
	backup  bool
	noSync  bool
	inspect bool
	asHost  string
}

func NewGet(a *app.App) *cobra.Command {
	f := &getFlags{}
	cmd := &cobra.Command{
		Use:   "get <secret-id>",
		Short: "Decrypt and install a secret granted to this machine",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGet(cmd.Context(), a, f, args[0])
		},
	}
	cmd.Flags().BoolVar(&f.stdout, "stdout", false, "print to stdout instead of installing")
	cmd.Flags().BoolVar(&f.force, "force", false, "overwrite an unmanaged destination file")
	cmd.Flags().BoolVar(&f.backup, "backup", false, "create a timestamped backup before overwriting")
	cmd.Flags().BoolVar(&f.noSync, "no-sync", false, "skip the sync step")
	cmd.Flags().BoolVar(&f.inspect, "inspect", false, "admin only: decrypt the secret from the vault and print it to stdout")
	cmd.Flags().StringVar(&f.asHost, "as-host", "", "admin only: decrypt the given host's bundle with the admin recovery key and print the secret to stdout")
	return cmd
}

func runGet(ctx context.Context, a *app.App, f *getFlags, secretID string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	home, err := resolveHome(a)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: resolve home: %w", err)}
	}

	if f.inspect || f.asHost != "" {
		if f.force || f.backup || f.stdout {
			return &ExitError{Code: ExitUsage, Err: errors.New("kauket: --inspect and --as-host cannot be combined with --stdout, --force, or --backup")}
		}
		if f.inspect && f.asHost != "" {
			return &ExitError{Code: ExitUsage, Err: errors.New("kauket: --inspect and --as-host cannot be combined")}
		}
		if f.inspect {
			return runInspect(ctx, a, f, secretID, home)
		}
		return runInspectHost(ctx, a, f, secretID, f.asHost, home)
	}

	cfg, err := config.LoadClient(home)
	if err != nil {
		if errors.Is(err, config.ErrNoConfig) {
			return &ExitError{Code: ExitUsage, Err: errors.New("kauket: no kauket store configured here; run 'kauket enroll' first")}
		}
		if errors.Is(err, config.ErrNotClient) {
			return &ExitError{Code: ExitUsage, Err: errors.New("kauket: kauket get requires client role")}
		}
		return &ExitError{Code: ExitUsage, Err: err}
	}

	if !f.noSync {
		if err := runGetSync(ctx, a, home, cfg, f.stdout); err != nil {
			return err
		}
	}

	bundlePath := filepath.Join(config.RepoDir(home), "bundles", cfg.Host.ID+".age")
	ct, err := os.ReadFile(bundlePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &ExitError{Code: ExitNotGranted, Err: errors.New("no approved bundle found for this machine\nrequest is pending or has not been approved")}
		}
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: read bundle: %w", err)}
	}

	identityPath := cfg.Host.IdentityPath
	if !filepath.IsAbs(identityPath) {
		identityPath = filepath.Join(home, identityPath)
	}
	b, err := bundle.DecodeHostBundle(ct, agebox.FileIdentityProvider{Path: identityPath})
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: errors.New("failed to decrypt bundle; this machine is probably not approved")}
	}

	secret, ok := b.Secrets[secretID]
	if !ok {
		return &ExitError{Code: ExitNotGranted, Err: fmt.Errorf("secret %s is not granted to this machine", secretID)}
	}

	content, err := base64.StdEncoding.DecodeString(secret.ContentBase64)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: decode secret content: %w", err)}
	}

	if f.stdout {
		if _, err := os.Stdout.Write(content); err != nil {
			return &ExitError{Code: ExitInstall, Err: fmt.Errorf("kauket: write stdout: %w", err)}
		}
		return nil
	}

	return installSecret(a, home, secretID, content, secret, f)
}

func runGetSync(ctx context.Context, a *app.App, home string, cfg *config.Client, stdoutMode bool) error {
	remoteURL := selectClientRemote(cfg)
	if remoteURL == "" {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: stored remote URL is empty")}
	}

	transport, err := buildGetTransport(home, cfg, remoteURL)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}

	now := a.Now
	if now == nil {
		now = time.Now
	}
	newStore := a.NewStore
	if newStore == nil {
		newStore = gitstore.OpenOrClone
	}
	store, err := newStore(ctx, gitstore.Config{
		RepoPath: config.RepoDir(home),
		URL:      remoteURL,
		LockPath: config.LockPath(home),
		Now:      now,
	}, transport)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	defer store.Close()

	if !stdoutMode {
		a.UI.Println("syncing store")
	}
	if err := store.Sync(ctx); err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}
	return nil
}

// runInspect implements `kauket get --inspect`: an admin-only path that reads a
// secret's plaintext straight from the admin vault and prints it to stdout. The
// admin holds the vault recipients, so no host identity or bundle is involved.
func runInspect(ctx context.Context, a *app.App, f *getFlags, secretID, home string) error {
	cfg, err := loadAdminForRead(home, "--inspect")
	if err != nil {
		return err
	}

	if !f.noSync {
		if err := runInspectSync(ctx, a, home, cfg); err != nil {
			return err
		}
	}

	vaultPath := filepath.Join(config.RepoDir(home), "admin", "vault.age")
	ct, err := os.ReadFile(vaultPath)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: read admin vault: %w", err)}
	}

	vault, err := bundle.DecodeVault(ct, agebox.FileIdentityProvider{Path: adminIdentityPath(cfg, home)})
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: decrypt admin vault: %w", err)}
	}

	secret, ok := vault.Secrets[secretID]
	if !ok {
		return &ExitError{Code: ExitNotGranted, Err: fmt.Errorf("secret %s is not defined in the vault", secretID)}
	}
	return writeSecretStdout(secret.ContentBase64)
}

// runInspectHost implements `kauket get --as-host <host-id>`: an admin-only path
// that decrypts a specific host's bundle with the admin recovery key and prints
// the secret to stdout. Unlike --inspect (which reads the whole vault), this
// shows exactly what that host will receive, with its grants applied.
func runInspectHost(ctx context.Context, a *app.App, f *getFlags, secretID, hostID, home string) error {
	cfg, err := loadAdminForRead(home, "--as-host")
	if err != nil {
		return err
	}

	if !f.noSync {
		if err := runInspectSync(ctx, a, home, cfg); err != nil {
			return err
		}
	}

	bundlePath := filepath.Join(config.RepoDir(home), "bundles", hostID+".age")
	ct, err := os.ReadFile(bundlePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &ExitError{Code: ExitNotGranted, Err: fmt.Errorf("no bundle found for host %s", hostID)}
		}
		return &ExitError{Code: ExitSync, Err: fmt.Errorf("kauket: read bundle: %w", err)}
	}

	b, err := bundle.DecodeHostBundle(ct, agebox.FileIdentityProvider{Path: adminIdentityPath(cfg, home)})
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: decrypt bundle for host %s: %w", hostID, err)}
	}

	secret, ok := b.Secrets[secretID]
	if !ok {
		return &ExitError{Code: ExitNotGranted, Err: fmt.Errorf("secret %s is not granted to host %s", secretID, hostID)}
	}
	return writeSecretStdout(secret.ContentBase64)
}

// loadAdminForRead loads the admin config for a read-only inspect path, mapping
// config errors to usage errors that name the flag being used.
func loadAdminForRead(home, flag string) (*config.Admin, error) {
	cfg, err := config.LoadAdmin(home)
	if err != nil {
		if errors.Is(err, config.ErrNoConfig) {
			return nil, &ExitError{Code: ExitUsage, Err: errors.New("kauket: no kauket store configured here; run 'kauket init' first")}
		}
		if errors.Is(err, config.ErrNotAdmin) {
			return nil, &ExitError{Code: ExitUsage, Err: fmt.Errorf("kauket: kauket get %s requires admin role", flag)}
		}
		return nil, &ExitError{Code: ExitUsage, Err: err}
	}
	return cfg, nil
}

func adminIdentityPath(cfg *config.Admin, home string) string {
	p := cfg.Admin.IdentityPath
	if !filepath.IsAbs(p) {
		p = filepath.Join(home, p)
	}
	return p
}

func writeSecretStdout(contentBase64 string) error {
	content, err := base64.StdEncoding.DecodeString(contentBase64)
	if err != nil {
		return &ExitError{Code: ExitCrypto, Err: fmt.Errorf("kauket: decode secret content: %w", err)}
	}
	if _, err := os.Stdout.Write(content); err != nil {
		return &ExitError{Code: ExitInstall, Err: fmt.Errorf("kauket: write stdout: %w", err)}
	}
	return nil
}

func runInspectSync(ctx context.Context, a *app.App, home string, cfg *config.Admin) error {
	remoteURL := cfg.Repo.RemoteHTTPS
	if remoteURL == "" {
		return &ExitError{Code: ExitUsage, Err: errors.New("kauket: stored remote URL is empty")}
	}

	transport, err := buildAdminSyncTransport(ctx, a, remoteURL, cfg.Repo.Owner)
	if err != nil {
		return &ExitError{Code: ExitSync, Err: err}
	}

	now := a.Now
	if now == nil {
		now = time.Now
	}
	newStore := a.NewStore
	if newStore == nil {
		newStore = gitstore.OpenOrClone
	}
	store, err := newStore(ctx, gitstore.Config{
		RepoPath: config.RepoDir(home),
		URL:      remoteURL,
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
	return nil
}

func selectClientRemote(cfg *config.Client) string {
	if strings.HasPrefix(cfg.Repo.RemoteHTTPS, "file://") {
		return cfg.Repo.RemoteHTTPS
	}
	if strings.TrimSpace(cfg.Repo.RemoteSSH) != "" {
		return cfg.Repo.RemoteSSH
	}
	return cfg.Repo.RemoteHTTPS
}

func buildGetTransport(home string, cfg *config.Client, remoteURL string) (gitstore.Transport, error) {
	deployKeyPath := cfg.Host.DeployKeyPath
	if deployKeyPath != "" && !filepath.IsAbs(deployKeyPath) {
		deployKeyPath = filepath.Join(home, deployKeyPath)
	}
	if deployKeyPath == "" {
		deployKeyPath = config.DeployKeyPath(home)
	}
	return gitstore.SelectTransportWithSSH(remoteURL, "", deployKeyPath)
}

func installSecret(a *app.App, home, secretID string, content []byte, secret model.BundleSecret, f *getFlags) error {
	spec, err := translateInstallSpec(secret.Install)
	if err != nil {
		return &ExitError{Code: ExitInstall, Err: err}
	}

	now := a.Now
	if now == nil {
		now = time.Now
	}
	opts := install.Options{
		Home:   home,
		Force:  f.force,
		Backup: f.backup,
		Now:    now,
	}
	res, err := install.InstallFile(secretID, content, spec, opts)
	if err != nil {
		return translateInstallError(err)
	}
	switch res.Status {
	case install.StatusCreated, install.StatusReplaced, install.StatusBackedUpAndReplaced:
		if res.Status == install.StatusBackedUpAndReplaced && res.BackupPath != "" {
			a.UI.Println(fmt.Sprintf("backup created %s", res.BackupPath))
		}
		a.UI.Println(fmt.Sprintf("creating %s", secret.Install.Destination))
	case install.StatusNoChange:
		a.UI.Println(fmt.Sprintf("%s already current", secret.Install.Destination))
	}
	return nil
}

func translateInstallSpec(m model.InstallSpec) (install.InstallSpec, error) {
	mode := m.Mode
	if strings.TrimSpace(mode) == "" {
		mode = "0600"
	}
	dirMode := m.DirectoryMode
	if strings.TrimSpace(dirMode) == "" {
		dirMode = "0700"
	}
	parsedMode, err := install.ParseMode(mode)
	if err != nil {
		return install.InstallSpec{}, fmt.Errorf("kauket: parse mode: %w", err)
	}
	parsedDirMode, err := install.ParseMode(dirMode)
	if err != nil {
		return install.InstallSpec{}, fmt.Errorf("kauket: parse directory mode: %w", err)
	}
	return install.InstallSpec{
		Destination:   m.Destination,
		Mode:          parsedMode,
		DirectoryMode: parsedDirMode,
	}, nil
}

func translateInstallError(err error) error {
	if errors.Is(err, install.ErrUnmanagedDestination) {
		return &ExitError{Code: ExitInstall, Err: errors.New("destination exists and was not installed by kauket")}
	}
	var symErr *install.SymlinkInPathError
	if errors.As(err, &symErr) {
		return &ExitError{Code: ExitInstall, Err: errors.New("refusing to write through symlink")}
	}
	return &ExitError{Code: ExitInstall, Err: fmt.Errorf("kauket: install: %w", err)}
}
