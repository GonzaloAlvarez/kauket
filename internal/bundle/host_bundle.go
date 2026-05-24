package bundle

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/model"
)

func BuildHostBundle(v model.Vault, hostID string, generatedAt time.Time, generation int) (model.Bundle, error) {
	host, ok := v.Hosts[hostID]
	if !ok {
		return model.Bundle{}, fmt.Errorf("%w: %s", ErrUnknownHost, hostID)
	}

	grantedProfiles := make(map[string]struct{}, len(host.GrantedProfiles))
	for _, p := range host.GrantedProfiles {
		grantedProfiles[p] = struct{}{}
	}
	grantedSecrets := make(map[string]struct{}, len(host.GrantedSecrets))
	for _, s := range host.GrantedSecrets {
		grantedSecrets[s] = struct{}{}
	}

	bundleSecrets := make(map[string]model.BundleSecret)
	for secretID, secret := range v.Secrets {
		include := false
		if _, ok := grantedSecrets[secretID]; ok {
			include = true
		}
		if !include {
			for _, profile := range secret.Profiles {
				if _, ok := grantedProfiles[profile]; ok {
					include = true
					break
				}
			}
		}
		if !include {
			continue
		}
		bundleSecrets[secretID] = model.BundleSecret{
			Kind:          secret.Kind,
			Install:       secret.Install,
			ContentBase64: secret.ContentBase64,
			SHA256:        secret.SHA256,
		}
	}

	return model.Bundle{
		Schema:           1,
		StoreID:          v.StoreID,
		HostID:           hostID,
		GeneratedAt:      generatedAt.UTC().Format(time.RFC3339),
		BundleGeneration: generation,
		Secrets:          bundleSecrets,
	}, nil
}

func EncodeHostBundle(b model.Bundle, hostRecip agebox.RecipientProvider, adminRecips agebox.RecipientProvider) ([]byte, error) {
	plaintext, err := model.MarshalCanonical(b)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal host bundle: %w", err)
	}
	padded, err := agebox.Wrap(plaintext, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to pad host bundle: %w", err)
	}
	combined := combinedRecipientProvider{a: hostRecip, b: adminRecips}
	ct, err := agebox.Encrypt(padded, combined)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt host bundle: %w", err)
	}
	return ct, nil
}

func DecodeHostBundle(ciphertext []byte, ip agebox.IdentityProvider) (model.Bundle, error) {
	padded, err := agebox.Decrypt(ciphertext, ip)
	if err != nil {
		return model.Bundle{}, fmt.Errorf("failed to open host bundle: %w", err)
	}
	plaintext, err := agebox.Unwrap(padded)
	if err != nil {
		return model.Bundle{}, fmt.Errorf("failed to unwrap host bundle: %w", err)
	}
	var b model.Bundle
	if err := json.Unmarshal(plaintext, &b); err != nil {
		return model.Bundle{}, fmt.Errorf("failed to unmarshal host bundle: %w", err)
	}
	return b, nil
}
