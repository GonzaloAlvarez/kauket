package githubauth

import (
	"bytes"
	"context"
	"os/exec"
)

type Shell interface {
	LookPath(name string) (string, error)
	Run(ctx context.Context, name string, args ...string) (stdout, stderr []byte, err error)
}

type SystemShell struct{}

func (SystemShell) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (SystemShell) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}
