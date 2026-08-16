package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/awsconfig"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/model"
	"github.com/spf13/cobra"
)

const defaultMaxSecretSize = 4 * 1024 * 1024

type addFlags struct {
	dest          string
	mode          string
	directoryMode string
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

	return runAddV2(ctx, a, home, cfg, f, secretID, content, spec, kind)
}
