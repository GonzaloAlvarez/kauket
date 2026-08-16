package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/gitstore"
	"github.com/gonzaloalvarez/kauket/internal/install"
	"github.com/gonzaloalvarez/kauket/internal/model"
	"github.com/spf13/cobra"
)

type getFlags struct {
	stdout bool
	force  bool
	backup bool
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
	return cmd
}

func runGet(ctx context.Context, a *app.App, f *getFlags, secretID string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	_, clientExists, err := resolveRoleHome(a, config.RoleClient)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	if !clientExists {
		adminHome, adminExists, err := resolveRoleHome(a, config.RoleAdmin)
		if err != nil {
			return &ExitError{Code: ExitUsage, Err: err}
		}
		if adminExists {
			adminCfg, err := config.LoadAdmin(adminHome)
			if err != nil {
				return &ExitError{Code: ExitUsage, Err: err}
			}
			if err := syncForRead(ctx, a, config.RoleAdmin, adminHome); err != nil {
				return err
			}
			if err := requireV2StoreDir(config.RepoDir(adminHome)); err != nil {
				return err
			}
			return getV2(a, adminHome, adminCfg.Admin.IdentityPath, adminCfg.V2, f, secretID)
		}
	}
	home, err := requireRoleHome(a, config.RoleClient, "kauket get")
	if err != nil {
		return err
	}

	cfg, err := config.LoadClient(home)
	if err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}

	if err := syncForRead(ctx, a, config.RoleClient, home); err != nil {
		return err
	}

	if err := requireV2StoreDir(config.RepoDir(home)); err != nil {
		return err
	}
	return getV2(a, home, cfg.Host.IdentityPath, cfg.V2, f, secretID)
}

func installPolicyFor(home string) *config.InstallPolicy {
	if cfg, err := config.LoadClient(home); err == nil {
		return cfg.Install
	}
	if cfg, err := config.LoadAdmin(home); err == nil {
		return cfg.Install
	}
	return nil
}

func applyInstallPolicy(opts *install.Options, home string) {
	if pol := installPolicyFor(home); pol != nil {
		opts.AllowedRoots = pol.AllowedRoots
		opts.AllowLooseModes = pol.AllowLooseModes
		opts.DeniedAWSKeys = pol.DeniedAWSKeys
	}
}

func installAWSProfileSecret(a *app.App, home, secretID string, content []byte, f *getFlags) error {
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
	applyInstallPolicy(&opts, home)
	res, err := install.InstallAWSProfile(secretID, content, opts)
	if err != nil {
		return translateInstallError(err)
	}
	changed := false
	for _, fr := range res.Files {
		switch fr.Status {
		case install.StatusCreated:
			changed = true
			a.UI.Println(fmt.Sprintf("creating %s", fr.Destination))
		case install.StatusReplaced, install.StatusBackedUpAndReplaced:
			changed = true
			if fr.BackupPath != "" {
				a.UI.Println(fmt.Sprintf("backup created %s", fr.BackupPath))
			}
			a.UI.Println(fmt.Sprintf("updating %s", fr.Destination))
		}
	}
	if !changed {
		a.UI.Println(fmt.Sprintf("profile %s already current", res.Profile))
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
	applyInstallPolicy(&opts, home)
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
	if errors.Is(err, install.ErrUnmanagedSection) {
		return &ExitError{Code: ExitInstall, Err: err}
	}
	if errors.Is(err, install.ErrUnmanagedDestination) {
		return &ExitError{Code: ExitInstall, Err: errors.New("destination exists and was not installed by kauket")}
	}
	var symErr *install.SymlinkInPathError
	if errors.As(err, &symErr) {
		return &ExitError{Code: ExitInstall, Err: errors.New("refusing to write through symlink")}
	}
	return &ExitError{Code: ExitInstall, Err: fmt.Errorf("kauket: install: %w", err)}
}
