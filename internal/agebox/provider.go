package agebox

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"filippo.io/age"
)

var ErrNoRecipients = errors.New("no recipients provided")

type IdentityProvider interface {
	Identities() ([]age.Identity, error)
}

type RecipientProvider interface {
	Recipients() ([]age.Recipient, error)
}

type FileIdentityProvider struct {
	Path string
}

func (p FileIdentityProvider) Identities() ([]age.Identity, error) {
	data, err := os.ReadFile(p.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read identity file %q: %w", p.Path, err)
	}
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to parse identity file %q: %w", p.Path, err)
	}
	return ids, nil
}

type X25519RecipientProvider struct {
	Strings []string
}

func (p X25519RecipientProvider) Recipients() ([]age.Recipient, error) {
	if len(p.Strings) == 0 {
		return nil, ErrNoRecipients
	}
	out := make([]age.Recipient, 0, len(p.Strings))
	for i, s := range p.Strings {
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			return nil, fmt.Errorf("failed to parse recipient at index %d: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}
