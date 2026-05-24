package agebox

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
)

const MaxPlaintext = 4 * 1024 * 1024

var (
	ErrNoIdentities      = errors.New("no identities provided")
	ErrPlaintextTooLarge = errors.New("plaintext exceeds MaxPlaintext")
)

func Encrypt(plaintext []byte, rp RecipientProvider) ([]byte, error) {
	if len(plaintext) > MaxPlaintext {
		return nil, ErrPlaintextTooLarge
	}
	recipients, err := rp.Recipients()
	if err != nil {
		return nil, err
	}
	if len(recipients) == 0 {
		return nil, ErrNoRecipients
	}
	var buf bytes.Buffer
	writer, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, fmt.Errorf("failed to start encryption: %w", err)
	}
	if _, err := io.Copy(writer, bytes.NewReader(plaintext)); err != nil {
		return nil, fmt.Errorf("failed to write plaintext: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize encryption: %w", err)
	}
	return buf.Bytes(), nil
}

func Decrypt(ciphertext []byte, ip IdentityProvider) ([]byte, error) {
	identities, err := ip.Identities()
	if err != nil {
		return nil, fmt.Errorf("failed to load identities: %w", err)
	}
	if len(identities) == 0 {
		return nil, ErrNoIdentities
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return nil, fmt.Errorf("failed to open decrypted stream: %w", err)
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted stream: %w", err)
	}
	return out, nil
}

func GenerateIdentity() (*age.X25519Identity, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity: %w", err)
	}
	return id, nil
}

func ParseIdentity(data []byte) ([]age.Identity, error) {
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to parse identity: %w", err)
	}
	return ids, nil
}
