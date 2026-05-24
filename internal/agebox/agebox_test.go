package agebox

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func writeIdentityFile(t *testing.T, id *age.X25519Identity) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "id.txt")
	if err := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	return path
}

func generatePair(t *testing.T) (admin, host *age.X25519Identity) {
	t.Helper()
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate admin: %v", err)
	}
	h, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate host: %v", err)
	}
	return a, h
}

func TestEncryptDecrypt(t *testing.T) {
	plaintext := []byte("kauket test payload v1")

	t.Run("encrypt to host only - host decrypts admin fails", func(t *testing.T) {
		admin, host := generatePair(t)
		rp := X25519RecipientProvider{Strings: []string{host.Recipient().String()}}
		ct, err := Encrypt(plaintext, rp)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		hostIP := FileIdentityProvider{Path: writeIdentityFile(t, host)}
		got, err := Decrypt(ct, hostIP)
		if err != nil {
			t.Fatalf("host decrypt: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("host decrypt mismatch")
		}
		adminIP := FileIdentityProvider{Path: writeIdentityFile(t, admin)}
		if _, err := Decrypt(ct, adminIP); err == nil {
			t.Fatalf("expected admin decrypt to fail")
		}
	})

	t.Run("encrypt to host plus admin - both decrypt", func(t *testing.T) {
		admin, host := generatePair(t)
		rp := X25519RecipientProvider{Strings: []string{host.Recipient().String(), admin.Recipient().String()}}
		ct, err := Encrypt(plaintext, rp)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		for name, id := range map[string]*age.X25519Identity{"host": host, "admin": admin} {
			ip := FileIdentityProvider{Path: writeIdentityFile(t, id)}
			got, err := Decrypt(ct, ip)
			if err != nil {
				t.Fatalf("%s decrypt: %v", name, err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("%s plaintext mismatch", name)
			}
		}
	})

	t.Run("wrong identity fails", func(t *testing.T) {
		_, host := generatePair(t)
		rp := X25519RecipientProvider{Strings: []string{host.Recipient().String()}}
		ct, err := Encrypt(plaintext, rp)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		other, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatalf("generate other: %v", err)
		}
		ip := FileIdentityProvider{Path: writeIdentityFile(t, other)}
		if _, err := Decrypt(ct, ip); err == nil {
			t.Fatalf("expected decrypt with wrong identity to fail")
		}
	})

	t.Run("corrupted ciphertext fails", func(t *testing.T) {
		_, host := generatePair(t)
		rp := X25519RecipientProvider{Strings: []string{host.Recipient().String()}}
		ct, err := Encrypt(plaintext, rp)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		if len(ct) < 200 {
			t.Fatalf("ciphertext unexpectedly short: %d", len(ct))
		}
		flipped := make([]byte, len(ct))
		copy(flipped, ct)
		flipIdx := len(flipped) - 10
		flipped[flipIdx] ^= 0xFF
		ip := FileIdentityProvider{Path: writeIdentityFile(t, host)}
		if _, err := Decrypt(flipped, ip); err == nil {
			t.Fatalf("expected decrypt of corrupted ciphertext to fail")
		}
	})

	t.Run("empty recipient list returns ErrNoRecipients", func(t *testing.T) {
		_, err := Encrypt(plaintext, X25519RecipientProvider{})
		if !errors.Is(err, ErrNoRecipients) {
			t.Fatalf("expected ErrNoRecipients, got %v", err)
		}
	})

	t.Run("same plaintext yields different ciphertext", func(t *testing.T) {
		_, host := generatePair(t)
		rp := X25519RecipientProvider{Strings: []string{host.Recipient().String()}}
		ct1, err := Encrypt(plaintext, rp)
		if err != nil {
			t.Fatalf("encrypt 1: %v", err)
		}
		ct2, err := Encrypt(plaintext, rp)
		if err != nil {
			t.Fatalf("encrypt 2: %v", err)
		}
		if bytes.Equal(ct1, ct2) {
			t.Fatalf("expected different ciphertexts due to age ephemerality")
		}
	})
}

type stubIdentityProvider struct {
	ids []age.Identity
	err error
}

func (s stubIdentityProvider) Identities() ([]age.Identity, error) {
	return s.ids, s.err
}

func TestDecryptNoIdentities(t *testing.T) {
	_, host := generatePair(t)
	rp := X25519RecipientProvider{Strings: []string{host.Recipient().String()}}
	ct, err := Encrypt([]byte("hi"), rp)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	_, err = Decrypt(ct, stubIdentityProvider{ids: nil, err: nil})
	if !errors.Is(err, ErrNoIdentities) {
		t.Fatalf("expected ErrNoIdentities, got %v", err)
	}
}

type stubRecipientProvider struct {
	rs  []age.Recipient
	err error
}

func (s stubRecipientProvider) Recipients() ([]age.Recipient, error) {
	return s.rs, s.err
}

func TestEncryptProviderErrorPropagates(t *testing.T) {
	sentinel := errors.New("provider boom")
	_, err := Encrypt([]byte("x"), stubRecipientProvider{rs: nil, err: sentinel})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel propagation, got %v", err)
	}
}

func TestEncryptRejectsOversizePlaintext(t *testing.T) {
	_, host := generatePair(t)
	rp := X25519RecipientProvider{Strings: []string{host.Recipient().String()}}
	too := make([]byte, MaxPlaintext+1)
	if _, err := Encrypt(too, rp); !errors.Is(err, ErrPlaintextTooLarge) {
		t.Fatalf("expected ErrPlaintextTooLarge, got %v", err)
	}
}

func TestGenerateAndParseIdentityRoundTrip(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	data := []byte(id.String() + "\n")
	parsed, err := ParseIdentity(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(parsed))
	}
}
