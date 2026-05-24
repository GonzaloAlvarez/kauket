package bundle

import (
	"crypto/rand"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

type Signer interface {
	Sign(payload []byte) (signature []byte, publicKeyFingerprint string, err error)
}

type Verifier interface {
	Verify(payload, signature []byte, sshPublicKey string) error
}

type Ed25519FileSigner struct {
	Path string
}

func (s Ed25519FileSigner) Sign(payload []byte) ([]byte, string, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read signer key %q: %w", s.Path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse signer key %q: %w", s.Path, err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, "", fmt.Errorf("signer key %q is not ed25519", s.Path)
	}
	sig, err := signer.Sign(rand.Reader, payload)
	if err != nil {
		return nil, "", fmt.Errorf("failed to sign payload: %w", err)
	}
	fpr := ssh.FingerprintSHA256(signer.PublicKey())
	return sig.Blob, fpr, nil
}

type Ed25519Verifier struct{}

func (Ed25519Verifier) Verify(payload, signature []byte, sshPublicKey string) error {
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshPublicKey))
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	if pubkey.Type() != ssh.KeyAlgoED25519 {
		return fmt.Errorf("public key is not ed25519")
	}
	if err := pubkey.Verify(payload, &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: signature}); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return nil
}
