package bundle

import (
	"encoding/json"
	"fmt"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/model"
)

func EncodeVault(v model.Vault, rp agebox.RecipientProvider) ([]byte, error) {
	plaintext, err := model.MarshalCanonical(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vault: %w", err)
	}
	padded, err := agebox.Wrap(plaintext, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to pad vault: %w", err)
	}
	ct, err := agebox.Encrypt(padded, rp)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt vault: %w", err)
	}
	return ct, nil
}

func DecodeVault(ciphertext []byte, ip agebox.IdentityProvider) (model.Vault, error) {
	padded, err := agebox.Decrypt(ciphertext, ip)
	if err != nil {
		return model.Vault{}, fmt.Errorf("failed to open vault: %w", err)
	}
	plaintext, err := agebox.Unwrap(padded)
	if err != nil {
		return model.Vault{}, fmt.Errorf("failed to unwrap vault: %w", err)
	}
	var v model.Vault
	if err := json.Unmarshal(plaintext, &v); err != nil {
		return model.Vault{}, fmt.Errorf("failed to unmarshal vault: %w", err)
	}
	return v, nil
}
