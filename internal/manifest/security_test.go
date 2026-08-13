package manifest

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
)

func fixedNow() func() time.Time {
	return func() time.Time { return time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC) }
}

type sealedStore struct {
	dir      string
	root     StoreRoot
	signer   bundle.Ed25519FileSigner
	signPub  string
	ownerIP  agebox.FileIdentityProvider
	ownerID  string
	ownerRec string
	recovery []string
	secret   []byte
}

func newSealedStore(t *testing.T) *sealedStore {
	t.Helper()
	dir := t.TempDir()
	signer, signPub := newTestSigner(t)
	_, ownerIP, ownerRecipient := newTestAgeIdentity(t)
	_, _, recoveryRecipient := newTestAgeIdentity(t)
	recovery := []string{recoveryRecipient}
	storeID := "ks_sealedstore1234"
	rootNode := "n_sealedroot123456"
	rootIndex := "x_sealedrootindex1"
	ownerID := "i_sealedowner12345"

	rootBody := ManifestBody{
		Schema: SchemaSealed, Kind: KindManifest, StoreID: storeID,
		NodeID: rootNode, Version: 1, UpdatedAt: "2026-08-13T00:00:00Z",
		Owners:        []Owner{{IID: ownerID, AgeRecipient: ownerRecipient, SignPubkey: signPub}},
		IndexObjectID: rootIndex,
	}
	tree := Tree{rootNode: rootBody}
	ix := Index{Schema: SchemaSealed, Kind: KindIndex, StoreID: storeID, NodeID: rootNode, Entries: map[string]IndexEntry{}}
	ixRec, _ := RecipientSet(ArtifactIndex, rootNode, "", tree, nil, recovery)
	ixCT, ixSHA, err := EncodeIndex(ix, agebox.X25519RecipientProvider{Strings: ixRec})
	if err != nil {
		t.Fatalf("encode root index: %v", err)
	}
	writeTestObject(t, dir, rootIndex, ixCT)
	rootBody.IndexSHA256 = ixSHA
	tree[rootNode] = rootBody
	signedRoot, _ := SignBody(rootBody, signer)
	mRec, _ := RecipientSet(ArtifactManifest, rootNode, "", tree, nil, recovery)
	mCT, _, err := EncodeManifest(ManifestFile{Body: signedRoot, Recipients: mRec}, agebox.X25519RecipientProvider{Strings: mRec})
	if err != nil {
		t.Fatalf("encode root manifest: %v", err)
	}
	writeTestObject(t, dir, rootNode, mCT)

	root := StoreRoot{
		Schema: SchemaSealed, Version: 1, StoreID: storeID, CreatedAt: "2026-08-13T00:00:00Z",
		Format: DefaultStoreFormat(), RootNodeID: rootNode,
		TrustAnchors: []TrustAnchor{{IID: ownerID, SignPubkey: signPub, AgeRecipient: ownerRecipient}},
		Recovery:     []RecoveryKey{{AgeRecipient: recoveryRecipient, SignPubkey: signPub}},
	}
	secret := []byte("SEALED SECRET BYTES")
	eng := &Engine{ObjectsDir: dir, Root: root, Pins: emptyPins(), Identity: ownerIP, Signer: signer, SignerPub: signPub, ActorID: ownerID, Now: fixedNow()}
	obj := &Object{Kind: "file", ContentBase64: base64.StdEncoding.EncodeToString(secret), SHA256: shaHex(secret)}
	if _, err := eng.Apply(Intent{Op: OpAdd, Path: []string{"aws", "profile"}, Key: "amzn-wanfe", Secret: obj}); err != nil {
		t.Fatalf("seed add: %v", err)
	}
	return &sealedStore{dir: dir, root: root, signer: signer, signPub: signPub, ownerIP: ownerIP, ownerID: ownerID, ownerRec: ownerRecipient, recovery: recovery, secret: secret}
}

func (s *sealedStore) engine() *Engine {
	return &Engine{ObjectsDir: s.dir, Root: s.root, Pins: emptyPins(), Identity: s.ownerIP, Signer: s.signer, SignerPub: s.signPub, ActorID: s.ownerID, Now: fixedNow()}
}

func readSealedSecretAs(t *testing.T, s *sealedStore, ip agebox.IdentityProvider, path ...string) ([]byte, error) {
	t.Helper()
	res, err := WalkSpine(s.dir, s.root, emptyPins(), ip, bundle.Ed25519Verifier{}, path)
	if err != nil {
		return nil, err
	}
	leaf := res.Nodes[res.SpineIDs[len(res.SpineIDs)-1]]
	ix, err := LoadIndex(s.dir, leaf.Body, ip)
	if err != nil {
		return nil, err
	}
	entry, ok := ix.Entries["amzn-wanfe"]
	if !ok {
		return nil, errors.New("entry missing")
	}
	obj, err := LoadObject(s.dir, entry, ip)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(obj.ContentBase64)
}

func TestChildNameMismatchRejected(t *testing.T) {
	signer, signPub := newTestSigner(t)
	root := StoreRoot{Schema: SchemaSealed, StoreID: "ks_x", RootNodeID: "n_root", TrustAnchors: []TrustAnchor{{SignPubkey: signPub}}}
	parent := ManifestBody{
		Schema: SchemaSealed, Kind: KindManifest, StoreID: "ks_x", NodeID: "n_parent",
		Children: []ChildAttestation{{NodeID: "n_child", Name: "aws", OwnerSignKeys: []string{signPub}}},
		Owners:   []Owner{{SignPubkey: signPub}},
	}
	childBody := ManifestBody{Schema: SchemaSealed, Kind: KindManifest, StoreID: "ks_x", NodeID: "n_child", Name: "awsx", Owners: []Owner{{SignPubkey: signPub}}}
	signed, err := SignBody(childBody, signer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	err = verifyNode(ManifestFile{Body: signed}, root, &parent, emptyPins(), bundle.Ed25519Verifier{})
	if !errors.Is(err, ErrUnattestedChild) {
		t.Fatalf("err = %v, want ErrUnattestedChild", err)
	}
}

func TestChildNameMatchAccepted(t *testing.T) {
	signer, signPub := newTestSigner(t)
	root := StoreRoot{Schema: SchemaSealed, StoreID: "ks_x", RootNodeID: "n_root", TrustAnchors: []TrustAnchor{{SignPubkey: signPub}}}
	parent := ManifestBody{
		Schema: SchemaSealed, Kind: KindManifest, StoreID: "ks_x", NodeID: "n_parent",
		Children: []ChildAttestation{{NodeID: "n_child", Name: "aws", OwnerSignKeys: []string{signPub}}},
		Owners:   []Owner{{SignPubkey: signPub}},
	}
	childBody := ManifestBody{Schema: SchemaSealed, Kind: KindManifest, StoreID: "ks_x", NodeID: "n_child", Name: "aws", Owners: []Owner{{SignPubkey: signPub}}}
	signed, err := SignBody(childBody, signer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := verifyNode(ManifestFile{Body: signed}, root, &parent, emptyPins(), bundle.Ed25519Verifier{}); err != nil {
		t.Fatalf("matching name rejected: %v", err)
	}
}

func TestGrantSubtreeReachesDescendantObject(t *testing.T) {
	s := newSealedStore(t)
	_, granteeIP, granteeRecipient := newTestAgeIdentity(t)
	grantee := IdentityRecord{ID: "h_granteeaaaaaaaaa", AgeRecipient: granteeRecipient}

	if _, err := s.engine().Apply(Intent{Op: OpGrant, Path: []string{"aws"}, Identity: grantee, Subtree: true}); err != nil {
		t.Fatalf("subtree grant: %v", err)
	}
	got, err := readSealedSecretAs(t, s, granteeIP, "aws", "profile")
	if err != nil {
		t.Fatalf("grantee could not read descendant secret: %v", err)
	}
	if string(got) != string(s.secret) {
		t.Fatalf("secret = %q, want %q", got, s.secret)
	}
}

func TestGrantNonSubtreeDoesNotReachDescendant(t *testing.T) {
	s := newSealedStore(t)
	_, granteeIP, granteeRecipient := newTestAgeIdentity(t)
	grantee := IdentityRecord{ID: "h_granteebbbbbbbbb", AgeRecipient: granteeRecipient}

	if _, err := s.engine().Apply(Intent{Op: OpGrant, Path: []string{"aws"}, Identity: grantee, Subtree: false}); err != nil {
		t.Fatalf("node grant: %v", err)
	}
	if _, err := readSealedSecretAs(t, s, granteeIP, "aws", "profile"); err == nil {
		t.Fatalf("non-subtree grant unexpectedly reached descendant secret")
	}
}

func TestRevokeSubtreeRemovesDescendantAccess(t *testing.T) {
	s := newSealedStore(t)
	_, granteeIP, granteeRecipient := newTestAgeIdentity(t)
	grantee := IdentityRecord{ID: "h_granteeccccccccc", AgeRecipient: granteeRecipient}

	if _, err := s.engine().Apply(Intent{Op: OpGrant, Path: []string{"aws"}, Identity: grantee, Subtree: true}); err != nil {
		t.Fatalf("subtree grant: %v", err)
	}
	if _, err := readSealedSecretAs(t, s, granteeIP, "aws", "profile"); err != nil {
		t.Fatalf("grantee should read before revoke: %v", err)
	}
	plan, err := s.engine().Apply(Intent{Op: OpRevoke, Path: []string{"aws"}, Identity: grantee, Subtree: true})
	if err != nil {
		t.Fatalf("subtree revoke: %v", err)
	}
	if _, err := readSealedSecretAs(t, s, granteeIP, "aws", "profile"); err == nil {
		t.Fatalf("grantee still reads descendant after subtree revoke")
	}
	found := false
	for _, r := range plan.Rotation {
		if strings.Contains(r, "amzn-wanfe") {
			found = true
		}
	}
	if !found {
		t.Fatalf("rotation list missing descendant entry: %v", plan.Rotation)
	}
}

func TestIndexHashBindingRejectsStaleIndex(t *testing.T) {
	ts := buildTestStore(t)
	body := ts.tree["n_walkprofile123456"]
	body.IndexSHA256 = strings.Repeat("0", 64)
	if _, err := LoadIndex(ts.dir, body, ts.ownerIP); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("err = %v, want ErrHashMismatch", err)
	}
}

func TestObjectHashBindingRejectsStaleObject(t *testing.T) {
	ts := buildTestStore(t)
	entry := ts.index.Entries["amzn-wanfe"]
	entry.ObjectSHA256 = strings.Repeat("0", 64)
	if _, err := LoadObject(ts.dir, entry, ts.ownerIP); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("err = %v, want ErrHashMismatch", err)
	}
}

func TestCheckPinRejectsOlderVersion(t *testing.T) {
	pins := &Pins{NodeVersions: map[string]int{"n_x": 5}}
	if err := checkPin(pins, ManifestBody{NodeID: "n_x", Version: 4}); !errors.Is(err, ErrRollback) {
		t.Fatalf("err = %v, want ErrRollback", err)
	}
	if err := checkPin(pins, ManifestBody{NodeID: "n_x", Version: 5}); err != nil {
		t.Fatalf("equal version rejected: %v", err)
	}
	if err := checkPin(pins, ManifestBody{NodeID: "n_fresh", Version: 1}); err != nil {
		t.Fatalf("fresh node rejected: %v", err)
	}
}

func TestSchema2StoreRemainsReadable(t *testing.T) {
	ts := buildTestStore(t)
	if ts.root.Sealed() {
		t.Fatalf("fixture should be an unsealed schema-2 store")
	}
	if _, err := WalkSpine(ts.dir, ts.root, emptyPins(), ts.ownerIP, bundle.Ed25519Verifier{}, []string{"aws", "profile"}); err != nil {
		t.Fatalf("new binary can no longer read a schema-2 store: %v", err)
	}
}

func TestSchema2StoreRootVerifiesWithoutVersion(t *testing.T) {
	signer, signPub := newTestSigner(t)
	root := fixtureStoreRoot()
	if root.Sealed() {
		t.Fatalf("fixture root should be schema 2")
	}
	doc, sig, err := SignStoreRoot(root, signer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if strings.Contains(string(doc), "\"version\"") {
		t.Fatalf("schema-2 store root must omit the version field for old-binary compatibility")
	}
	if _, _, err := VerifyStoreRoot(doc, sig, []string{signPub}, bundle.Ed25519Verifier{}); err != nil {
		t.Fatalf("schema-2 store root failed to verify on the new binary: %v", err)
	}
}

func TestStoreRootVersionCoveredBySignature(t *testing.T) {
	signer, signPub := newTestSigner(t)
	root := fixtureStoreRoot()
	root.Schema = SchemaSealed
	root.Version = 1
	doc, sig, err := SignStoreRoot(root, signer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	tampered := []byte(strings.Replace(string(doc), "\"version\": 1", "\"version\": 2", 1))
	if _, _, err := VerifyStoreRoot(tampered, sig, []string{signPub}, bundle.Ed25519Verifier{}); !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("version tamper: err = %v, want ErrUntrustedSigner", err)
	}
}
