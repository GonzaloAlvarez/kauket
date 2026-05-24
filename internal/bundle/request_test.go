package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/model"
)

func writeEd25519DeployKey(t *testing.T, name string) (privPath, pubAuthorized string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "kauket-deploy")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	privPath = filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(privPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	pubAuthorized = string(bytes.TrimRight(ssh.MarshalAuthorizedKey(sshPub), "\n"))
	return privPath, pubAuthorized
}

func buildSampleRequest(hostPub string) model.Request {
	return model.Request{
		Schema:    1,
		StoreID:   "ks_6me7bk1f9s4xz2qa",
		RequestID: "rq_m5w8r0qf2p1x9z6a",
		CreatedAt: "2026-05-24T00:00:00Z",
		Host: model.RequestHost{
			ID:                 "h_7j4v6m2q9xk3p8da",
			DisplayName:        "machine2",
			ReportedHostname:   "r730xd-debian",
			OS:                 "linux",
			Arch:               "amd64",
			AgeRecipient:       "age1example",
			GitDeployPublicKey: hostPub,
		},
		Requested: model.RequestedItems{Profiles: []string{"ssh"}, Secrets: []string{}},
	}
}

func TestEncodeDecodeRequestRoundTrip(t *testing.T) {
	admin := generateIdentity(t)
	adminRecips := agebox.X25519RecipientProvider{Strings: []string{admin.Recipient().String()}}
	privPath, pubAuthorized := writeEd25519DeployKey(t, "deploy_key")

	r := buildSampleRequest(pubAuthorized + " kauket-deploy")
	ct, err := EncodeRequest(r, Ed25519FileSigner{Path: privPath}, adminRecips)
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	ip := agebox.FileIdentityProvider{Path: writeIdentityFile(t, "admin.txt", admin)}
	got, err := DecodeRequest(ct, ip, Ed25519Verifier{})
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if got.Signature == nil {
		t.Fatalf("expected signature to be populated")
	}
	if got.Signature.Algorithm != "ed25519" {
		t.Fatalf("Algorithm: got %q, want ed25519", got.Signature.Algorithm)
	}
	if got.Signature.PublicKeyFingerprint == "" {
		t.Fatalf("PublicKeyFingerprint is empty")
	}
	if got.Signature.SignatureBase64 == "" {
		t.Fatalf("SignatureBase64 is empty")
	}
	if got.StoreID != r.StoreID {
		t.Fatalf("StoreID: got %q, want %q", got.StoreID, r.StoreID)
	}
	if got.RequestID != r.RequestID {
		t.Fatalf("RequestID: got %q, want %q", got.RequestID, r.RequestID)
	}
	if got.Host.ID != r.Host.ID {
		t.Fatalf("Host.ID: got %q, want %q", got.Host.ID, r.Host.ID)
	}
	if got.Host.GitDeployPublicKey != r.Host.GitDeployPublicKey {
		t.Fatalf("Host.GitDeployPublicKey: got %q, want %q", got.Host.GitDeployPublicKey, r.Host.GitDeployPublicKey)
	}
	if len(got.Requested.Profiles) != 1 || got.Requested.Profiles[0] != "ssh" {
		t.Fatalf("Requested.Profiles: got %v, want [ssh]", got.Requested.Profiles)
	}
}

func TestDecodeRequestUnsignedReturnsSentinel(t *testing.T) {
	admin := generateIdentity(t)
	adminRecips := agebox.X25519RecipientProvider{Strings: []string{admin.Recipient().String()}}

	r := buildSampleRequest("ssh-ed25519 AAAA kauket-deploy")
	r.Signature = nil
	plaintext, err := model.MarshalCanonical(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	padded, err := agebox.Wrap(plaintext, 0)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	ct, err := agebox.Encrypt(padded, adminRecips)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ip := agebox.FileIdentityProvider{Path: writeIdentityFile(t, "admin.txt", admin)}
	_, err = DecodeRequest(ct, ip, Ed25519Verifier{})
	if !errors.Is(err, ErrUnsignedRequest) {
		t.Fatalf("expected ErrUnsignedRequest, got %v", err)
	}
}

func TestDecodeRequestTamperedSignatureBytes(t *testing.T) {
	admin := generateIdentity(t)
	adminRecips := agebox.X25519RecipientProvider{Strings: []string{admin.Recipient().String()}}
	privPath, pubAuthorized := writeEd25519DeployKey(t, "deploy_key")

	r := buildSampleRequest(pubAuthorized + " kauket-deploy")
	ct, err := EncodeRequest(r, Ed25519FileSigner{Path: privPath}, adminRecips)
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	ip := agebox.FileIdentityProvider{Path: writeIdentityFile(t, "admin.txt", admin)}
	got, err := DecodeRequest(ct, ip, Ed25519Verifier{})
	if err != nil {
		t.Fatalf("initial DecodeRequest: %v", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(got.Signature.SignatureBase64)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sigBytes[0] ^= 0xFF
	got.Signature.SignatureBase64 = base64.StdEncoding.EncodeToString(sigBytes)
	tampered, err := model.MarshalCanonical(got)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	padded, err := agebox.Wrap(tampered, 0)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	badCT, err := agebox.Encrypt(padded, adminRecips)
	if err != nil {
		t.Fatalf("re-encrypt: %v", err)
	}
	_, err = DecodeRequest(badCT, ip, Ed25519Verifier{})
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestDecodeRequestTamperedPayloadWithReSignature(t *testing.T) {
	admin := generateIdentity(t)
	adminRecips := agebox.X25519RecipientProvider{Strings: []string{admin.Recipient().String()}}
	_, pubAuthorized := writeEd25519DeployKey(t, "deploy_key")

	r := buildSampleRequest(pubAuthorized + " kauket-deploy")

	attackerPriv, _ := writeEd25519DeployKey(t, "attacker_key")
	r.Host.ID = "h_attackerctrlhost"
	ct, err := EncodeRequest(r, Ed25519FileSigner{Path: attackerPriv}, adminRecips)
	if err != nil {
		t.Fatalf("EncodeRequest (attacker): %v", err)
	}
	ip := agebox.FileIdentityProvider{Path: writeIdentityFile(t, "admin.txt", admin)}
	_, err = DecodeRequest(ct, ip, Ed25519Verifier{})
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for mismatched signer, got %v", err)
	}
}

func TestDecodeRequestSubstitutedPublicKey(t *testing.T) {
	admin := generateIdentity(t)
	adminRecips := agebox.X25519RecipientProvider{Strings: []string{admin.Recipient().String()}}
	privPath, pubAuthorized := writeEd25519DeployKey(t, "deploy_key")

	r := buildSampleRequest(pubAuthorized + " kauket-deploy")
	ct, err := EncodeRequest(r, Ed25519FileSigner{Path: privPath}, adminRecips)
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	ip := agebox.FileIdentityProvider{Path: writeIdentityFile(t, "admin.txt", admin)}
	decoded, err := DecodeRequest(ct, ip, Ed25519Verifier{})
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}

	_, otherPub := writeEd25519DeployKey(t, "other_key")
	decoded.Host.GitDeployPublicKey = otherPub + " kauket-deploy"
	plaintext, err := model.MarshalCanonical(decoded)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	padded, err := agebox.Wrap(plaintext, 0)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	badCT, err := agebox.Encrypt(padded, adminRecips)
	if err != nil {
		t.Fatalf("re-encrypt: %v", err)
	}
	_, err = DecodeRequest(badCT, ip, Ed25519Verifier{})
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for substituted pubkey, got %v", err)
	}
}

func TestEd25519SignerRejectsRsaKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage")
	if err := os.WriteFile(path, []byte("not a private key"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err := Ed25519FileSigner{Path: path}.Sign([]byte("payload"))
	if err == nil {
		t.Fatalf("expected error on non-key file")
	}
}

func TestEd25519SignerProducesVerifiableSignature(t *testing.T) {
	privPath, pubAuthorized := writeEd25519DeployKey(t, "deploy_key")
	payload := []byte("hello world")
	sig, fpr, err := Ed25519FileSigner{Path: privPath}.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if fpr == "" {
		t.Fatalf("empty fingerprint")
	}
	if err := (Ed25519Verifier{}).Verify(payload, sig, pubAuthorized); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := (Ed25519Verifier{}).Verify([]byte("different"), sig, pubAuthorized); err == nil {
		t.Fatalf("expected verify of different payload to fail")
	}
}
