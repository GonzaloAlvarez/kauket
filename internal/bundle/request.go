package bundle

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/model"
)

func EncodeRequest(r model.Request, s Signer, adminRecips agebox.RecipientProvider) ([]byte, error) {
	r.Signature = nil
	payload, err := model.MarshalCanonical(r)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request payload: %w", err)
	}
	sig, fpr, err := s.Sign(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}
	r.Signature = &model.RequestSignature{
		Algorithm:            "ed25519",
		PublicKeyFingerprint: fpr,
		SignatureBase64:      base64.StdEncoding.EncodeToString(sig),
	}
	complete, err := model.MarshalCanonical(r)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed request: %w", err)
	}
	padded, err := agebox.Wrap(complete, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to pad request: %w", err)
	}
	ct, err := agebox.Encrypt(padded, adminRecips)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt request: %w", err)
	}
	return ct, nil
}

func DecodeRequest(ciphertext []byte, ip agebox.IdentityProvider, v Verifier) (model.Request, error) {
	padded, err := agebox.Decrypt(ciphertext, ip)
	if err != nil {
		return model.Request{}, fmt.Errorf("failed to open request: %w", err)
	}
	plaintext, err := agebox.Unwrap(padded)
	if err != nil {
		return model.Request{}, fmt.Errorf("failed to unwrap request: %w", err)
	}
	var r model.Request
	if err := json.Unmarshal(plaintext, &r); err != nil {
		return model.Request{}, fmt.Errorf("failed to unmarshal request: %w", err)
	}
	if r.Signature == nil {
		return model.Request{}, ErrUnsignedRequest
	}
	sigCopy := *r.Signature
	r.Signature = nil
	payload, err := model.MarshalCanonical(r)
	if err != nil {
		return model.Request{}, fmt.Errorf("failed to marshal request payload: %w", err)
	}
	r.Signature = &sigCopy
	sigBytes, err := base64.StdEncoding.DecodeString(sigCopy.SignatureBase64)
	if err != nil {
		return model.Request{}, fmt.Errorf("failed to decode signature: %w", err)
	}
	if err := v.Verify(payload, sigBytes, r.Host.GitDeployPublicKey); err != nil {
		if errors.Is(err, ErrInvalidSignature) {
			return model.Request{}, err
		}
		return model.Request{}, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return r, nil
}
