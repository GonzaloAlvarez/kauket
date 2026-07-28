package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	cryptossh "golang.org/x/crypto/ssh"
)

func newTestSigner(t *testing.T) (bundle.Ed25519FileSigner, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	block, err := cryptossh.MarshalPrivateKey(priv, "kauket-test")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "sign_key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	sshPub, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh public key: %v", err)
	}
	authorized := strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(sshPub)))
	return bundle.Ed25519FileSigner{Path: path}, authorized
}

func newTestAgeIdentity(t *testing.T) (*age.X25519Identity, agebox.FileIdentityProvider, string) {
	t.Helper()
	id, err := agebox.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	path := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	return id, agebox.FileIdentityProvider{Path: path}, id.Recipient().String()
}

func fixtureBody() ManifestBody {
	return ManifestBody{
		Schema:  Schema,
		Kind:    KindManifest,
		StoreID: "ks_fixturestore1234",
		NodeID:  "n_fixturenode123456",
		Version: 3,

		UpdatedAt: "2026-07-28T00:00:00Z",
		Name:      "profile",
		ParentID:  "n_fixtureparent1234",
		Children: []ChildAttestation{
			{NodeID: "n_fixturechild12345", OwnerSignKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureChildOwnerKey000000000000000000000"}},
		},
		Owners: []Owner{
			{IID: "i_fixtureowner12345", AgeRecipient: "age1fixtureowner", SignPubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOwnerSignKey00000000000000000000"},
		},
		Readers: []Member{
			{IID: "h_fixturereader1234", AgeRecipient: "age1fixturereader"},
		},
		ExtraReaders: []Member{
			{IID: "i_fixtureentryread1", AgeRecipient: "age1fixtureentryreader"},
		},
		IndexObjectID:      "x_fixtureindex12345",
		IndexSHA256:        "0000000000000000000000000000000000000000000000000000000000000000",
		PrevManifestSHA256: "",
	}
}

func fixtureIndex() Index {
	return Index{
		Schema:  Schema,
		Kind:    KindIndex,
		StoreID: "ks_fixturestore1234",
		NodeID:  "n_fixturenode123456",
		Entries: map[string]IndexEntry{
			"amzn-wanfe": {
				ObjectID:     "o_fixtureobject1234",
				ObjectSHA256: "1111111111111111111111111111111111111111111111111111111111111111",
				Kind:         "aws_profile",
				Readers:      []Member{{IID: "i_fixtureentryread1", AgeRecipient: "age1fixtureentryreader"}},
				CreatedAt:    "2026-07-28T00:00:00Z",
				UpdatedAt:    "2026-07-28T00:00:00Z",
			},
		},
	}
}

func fixtureObject() Object {
	return Object{
		Schema:        Schema,
		Kind:          "file",
		StoreID:       "ks_fixturestore1234",
		ObjectID:      "o_fixtureobject1234",
		ContentBase64: "UFJJVkFURSBLRVkgQk9EWQ==",
		SHA256:        "2222222222222222222222222222222222222222222222222222222222222222",
		CreatedAt:     "2026-07-28T00:00:00Z",
		UpdatedAt:     "2026-07-28T00:00:00Z",
	}
}

func fixtureStoreRoot() StoreRoot {
	return StoreRoot{
		Schema:     Schema,
		StoreID:    "ks_fixturestore1234",
		CreatedAt:  "2026-07-28T00:00:00Z",
		Format:     DefaultStoreFormat(),
		GitHub:     StoreGitHub{Owner: "GonzaloAlvarez", Repo: "kauket-store", DefaultBranch: "main"},
		RootNodeID: "n_fixtureroot123456",
		TrustAnchors: []TrustAnchor{
			{IID: "i_fixtureowner12345", SignPubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOwnerSignKey00000000000000000000"},
		},
		Recovery: []RecoveryKey{
			{AgeRecipient: "age1fixturerecovery", SignPubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureRecoverySignKey0000000000000000"},
		},
		FrozenV1: false,
	}
}
