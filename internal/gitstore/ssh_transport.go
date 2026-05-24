package gitstore

import (
	_ "embed"
	"errors"
	"fmt"
	"os"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/skeema/knownhosts"
	cryptossh "golang.org/x/crypto/ssh"
)

//go:embed github_known_hosts.txt
var githubKnownHostsBytes []byte

type SSHDeployKeyTransport struct {
	DeployKeyPath string
	knownHosts    cryptossh.HostKeyCallback
	signer        cryptossh.Signer
}

func NewSSHDeployKeyTransport(deployKeyPath string) (*SSHDeployKeyTransport, error) {
	if deployKeyPath == "" {
		return nil, errors.New("kauket: ssh deploy key path is empty")
	}
	info, err := os.Stat(deployKeyPath)
	if err != nil {
		return nil, fmt.Errorf("kauket: stat deploy key: %w", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		return nil, fmt.Errorf("kauket: deploy key %s has mode %o, want 0600", deployKeyPath, mode)
	}
	keyBytes, err := os.ReadFile(deployKeyPath)
	if err != nil {
		return nil, fmt.Errorf("kauket: read deploy key: %w", err)
	}
	signer, err := cryptossh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("kauket: parse deploy key: %w", err)
	}
	if signer.PublicKey().Type() != cryptossh.KeyAlgoED25519 {
		return nil, fmt.Errorf("kauket: deploy key must be ed25519, got %s", signer.PublicKey().Type())
	}

	cb, err := loadEmbeddedKnownHosts()
	if err != nil {
		return nil, err
	}

	return &SSHDeployKeyTransport{
		DeployKeyPath: deployKeyPath,
		knownHosts:    cb,
		signer:        signer,
	}, nil
}

func (t *SSHDeployKeyTransport) Auth() transport.AuthMethod {
	return &ssh.PublicKeys{
		User:   "git",
		Signer: t.signer,
		HostKeyCallbackHelper: ssh.HostKeyCallbackHelper{
			HostKeyCallback: t.knownHosts,
		},
	}
}

func loadEmbeddedKnownHosts() (cryptossh.HostKeyCallback, error) {
	f, err := os.CreateTemp("", "kauket-known-hosts-*")
	if err != nil {
		return nil, fmt.Errorf("kauket: create temp known_hosts: %w", err)
	}
	path := f.Name()
	if _, err := f.Write(githubKnownHostsBytes); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("kauket: write temp known_hosts: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("kauket: close temp known_hosts: %w", err)
	}
	hkcb, err := knownhosts.New(path)
	_ = os.Remove(path)
	if err != nil {
		return nil, fmt.Errorf("kauket: parse known_hosts: %w", err)
	}
	return hkcb.HostKeyCallback(), nil
}
