package bundle

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/model"
)

func writeIdentityFile(t *testing.T, name string, id *age.X25519Identity) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatalf("write identity %q: %v", name, err)
	}
	return path
}

func generateIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := agebox.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

func buildSampleVault(t *testing.T) (model.Vault, *age.X25519Identity, *age.X25519Identity) {
	t.Helper()
	admin1 := generateIdentity(t)
	admin2 := generateIdentity(t)

	v := model.Vault{
		Schema:    1,
		StoreID:   "ks_6me7bk1f9s4xz2qa",
		CreatedAt: "2026-05-24T00:00:00Z",
		UpdatedAt: "2026-05-24T00:00:00Z",
		Admins: []model.AdminRecipient{
			{ID: "ar_aaaaaaaaaaaaaaaa", Recipient: admin1.Recipient().String(), CreatedAt: "2026-05-24T00:00:00Z"},
			{ID: "ar_bbbbbbbbbbbbbbbb", Recipient: admin2.Recipient().String(), CreatedAt: "2026-05-24T00:00:00Z"},
		},
		Profiles: map[string]model.Profile{
			"ssh": {Description: "ssh"},
			"aws": {Description: "aws"},
		},
		Secrets: map[string]model.Secret{
			"ssh.main_private_key": {
				SecretObjectID: "s_aaaaaaaaaaaaaaaa",
				Kind:           "file",
				Profiles:       []string{"ssh"},
				Install:        model.InstallSpec{Destination: "~/.ssh/main_private_key", Mode: "0600", DirectoryMode: "0700"},
				ContentBase64:  "QUFBQQ==",
				SHA256:         "deadbeef",
				CreatedAt:      "2026-05-24T00:00:00Z",
				UpdatedAt:      "2026-05-24T00:00:00Z",
			},
			"aws.primary_account.key_file": {
				SecretObjectID: "s_bbbbbbbbbbbbbbbb",
				Kind:           "file",
				Profiles:       []string{"aws"},
				Install:        model.InstallSpec{Destination: "~/.aws/credentials", Mode: "0600", DirectoryMode: "0700"},
				ContentBase64:  "QkJCQg==",
				SHA256:         "cafebabe",
				CreatedAt:      "2026-05-24T00:00:00Z",
				UpdatedAt:      "2026-05-24T00:00:00Z",
			},
			"cloudflare.dns_api_token": {
				SecretObjectID: "s_cccccccccccccccc",
				Kind:           "file",
				Profiles:       []string{},
				Install:        model.InstallSpec{Destination: "~/.cf/token", Mode: "0600", DirectoryMode: "0700"},
				ContentBase64:  "Q0NDQw==",
				SHA256:         "feedface",
				CreatedAt:      "2026-05-24T00:00:00Z",
				UpdatedAt:      "2026-05-24T00:00:00Z",
			},
		},
		Hosts: map[string]model.Host{
			"h_7j4v6m2q9xk3p8da": {
				DisplayName:          "machine2",
				ReportedHostname:     "r730xd-debian",
				AgeRecipient:         "age1host",
				DeployKeyFingerprint: "SHA256:host",
				GrantedProfiles:      []string{"ssh"},
				GrantedSecrets:       []string{},
				CreatedAt:            "2026-05-24T00:00:00Z",
				ApprovedAt:           "2026-05-24T00:00:00Z",
			},
		},
		Requests: map[string]model.RequestRecord{},
	}
	return v, admin1, admin2
}

func TestEncodeDecodeVaultRoundTrip(t *testing.T) {
	v, admin1, admin2 := buildSampleVault(t)
	adminRecips := agebox.X25519RecipientProvider{
		Strings: []string{
			admin1.Recipient().String(),
			admin2.Recipient().String(),
		},
	}
	ct, err := EncodeVault(v, adminRecips)
	if err != nil {
		t.Fatalf("EncodeVault: %v", err)
	}
	for name, id := range map[string]*age.X25519Identity{"admin1": admin1, "admin2": admin2} {
		ip := agebox.FileIdentityProvider{Path: writeIdentityFile(t, name+".txt", id)}
		decoded, err := DecodeVault(ct, ip)
		if err != nil {
			t.Fatalf("%s decode: %v", name, err)
		}
		first, err := model.MarshalCanonical(v)
		if err != nil {
			t.Fatalf("marshal original: %v", err)
		}
		second, err := model.MarshalCanonical(decoded)
		if err != nil {
			t.Fatalf("marshal decoded: %v", err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("%s canonical bytes differ:\n got: %s\nwant: %s", name, second, first)
		}
	}
}

func TestDecodeVaultWrongIdentityFails(t *testing.T) {
	v, admin1, admin2 := buildSampleVault(t)
	adminRecips := agebox.X25519RecipientProvider{
		Strings: []string{admin1.Recipient().String(), admin2.Recipient().String()},
	}
	ct, err := EncodeVault(v, adminRecips)
	if err != nil {
		t.Fatalf("EncodeVault: %v", err)
	}
	other := generateIdentity(t)
	ip := agebox.FileIdentityProvider{Path: writeIdentityFile(t, "other.txt", other)}
	if _, err := DecodeVault(ct, ip); err == nil {
		t.Fatalf("expected decode with non-admin identity to fail")
	}
}

func TestDecodeVaultGarbageCiphertextFails(t *testing.T) {
	admin := generateIdentity(t)
	ip := agebox.FileIdentityProvider{Path: writeIdentityFile(t, "admin.txt", admin)}
	if _, err := DecodeVault([]byte("this is not age ciphertext"), ip); err == nil {
		t.Fatalf("expected garbage ciphertext to fail")
	}
}

func TestDecodeVaultErrorMessageHidesPlaintext(t *testing.T) {
	v, admin1, _ := buildSampleVault(t)
	adminRecips := agebox.X25519RecipientProvider{Strings: []string{admin1.Recipient().String()}}
	ct, err := EncodeVault(v, adminRecips)
	if err != nil {
		t.Fatalf("EncodeVault: %v", err)
	}
	other := generateIdentity(t)
	ip := agebox.FileIdentityProvider{Path: writeIdentityFile(t, "other.txt", other)}
	_, err = DecodeVault(ct, ip)
	if err == nil {
		t.Fatalf("expected decryption failure")
	}
	msg := err.Error()
	if !bytes.Contains([]byte(msg), []byte("failed to open vault")) {
		t.Fatalf("expected wrapped vault open error, got %q", msg)
	}
	disallowed := []string{
		"ssh.main_private_key",
		"main_private_key",
		admin1.Recipient().String(),
	}
	for _, d := range disallowed {
		if bytes.Contains([]byte(msg), []byte(d)) {
			t.Fatalf("error message leaks %q: %s", d, msg)
		}
	}
}
