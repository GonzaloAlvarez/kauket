package manifest

import (
	"encoding/base64"
	"errors"
	"os"
	"testing"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
)

type testStore struct {
	dir          string
	root         StoreRoot
	ownerSigner  bundle.Ed25519FileSigner
	ownerSignPub string
	ownerIP      agebox.FileIdentityProvider
	readerIP     agebox.FileIdentityProvider
	recoveryIP   agebox.FileIdentityProvider
	tree         Tree
	index        Index
	secret       []byte
}

func buildTestStore(t *testing.T) *testStore {
	t.Helper()
	dir := t.TempDir()
	ownerSigner, ownerSignPub := newTestSigner(t)
	_, ownerIP, ownerRecipient := newTestAgeIdentity(t)
	_, readerIP, readerRecipient := newTestAgeIdentity(t)
	_, recoveryIP, recoveryRecipient := newTestAgeIdentity(t)
	recovery := []string{recoveryRecipient}

	secret := []byte("SECRET CONTENT BYTES")
	object := Object{
		Schema:        Schema,
		Kind:          "file",
		StoreID:       "ks_walkteststore123",
		ObjectID:      "o_walkobject1234567",
		ContentBase64: base64.StdEncoding.EncodeToString(secret),
		SHA256:        shaHex(secret),
		CreatedAt:     "2026-07-28T00:00:00Z",
		UpdatedAt:     "2026-07-28T00:00:00Z",
	}

	index := Index{
		Schema:  Schema,
		Kind:    KindIndex,
		StoreID: "ks_walkteststore123",
		NodeID:  "n_walkprofile123456",
		Entries: map[string]IndexEntry{},
	}

	ownerRef := Owner{IID: "i_walkowner1234567", AgeRecipient: ownerRecipient, SignPubkey: ownerSignPub}
	readerRef := Member{IID: "h_walkreader123456", AgeRecipient: readerRecipient}

	tree := Tree{
		"n_walkroot12345678": {
			Schema: Schema, Kind: KindManifest, StoreID: "ks_walkteststore123",
			NodeID: "n_walkroot12345678", Version: 1, UpdatedAt: "2026-07-28T00:00:00Z",
			Name: "", ParentID: "",
			Children: []ChildAttestation{{NodeID: "n_walkaws123456789", OwnerSignKeys: []string{ownerSignPub}}},
			Owners:   []Owner{ownerRef},
		},
		"n_walkaws123456789": {
			Schema: Schema, Kind: KindManifest, StoreID: "ks_walkteststore123",
			NodeID: "n_walkaws123456789", Version: 1, UpdatedAt: "2026-07-28T00:00:00Z",
			Name: "aws", ParentID: "n_walkroot12345678",
			Children: []ChildAttestation{{NodeID: "n_walkprofile123456", OwnerSignKeys: []string{ownerSignPub}}},
			Owners:   []Owner{ownerRef},
		},
		"n_walkprofile123456": {
			Schema: Schema, Kind: KindManifest, StoreID: "ks_walkteststore123",
			NodeID: "n_walkprofile123456", Version: 1, UpdatedAt: "2026-07-28T00:00:00Z",
			Name: "profile", ParentID: "n_walkaws123456789",
			Owners:  []Owner{ownerRef},
			Readers: []Member{readerRef},
		},
	}

	objRecipients, err := RecipientSet(ArtifactObject, "n_walkprofile123456", "amzn-wanfe", tree, &Index{Entries: map[string]IndexEntry{"amzn-wanfe": {}}}, recovery)
	if err != nil {
		t.Fatalf("object recipients: %v", err)
	}
	objCT, objSHA, err := EncodeObject(object, agebox.X25519RecipientProvider{Strings: objRecipients})
	if err != nil {
		t.Fatalf("encode object: %v", err)
	}
	writeTestObject(t, dir, object.ObjectID, objCT)

	index.Entries["amzn-wanfe"] = IndexEntry{
		ObjectID: object.ObjectID, ObjectSHA256: objSHA, Kind: "file",
		CreatedAt: "2026-07-28T00:00:00Z", UpdatedAt: "2026-07-28T00:00:00Z",
	}
	ixRecipients, err := RecipientSet(ArtifactIndex, "n_walkprofile123456", "", tree, nil, recovery)
	if err != nil {
		t.Fatalf("index recipients: %v", err)
	}
	ixCT, ixSHA, err := EncodeIndex(index, agebox.X25519RecipientProvider{Strings: ixRecipients})
	if err != nil {
		t.Fatalf("encode index: %v", err)
	}
	writeTestObject(t, dir, "x_walkindex1234567", ixCT)

	profileBody := tree["n_walkprofile123456"]
	profileBody.IndexObjectID = "x_walkindex1234567"
	profileBody.IndexSHA256 = ixSHA
	tree["n_walkprofile123456"] = profileBody

	for id, body := range tree {
		signed, err := SignBody(body, ownerSigner)
		if err != nil {
			t.Fatalf("sign %s: %v", id, err)
		}
		recipients, err := RecipientSet(ArtifactManifest, id, "", tree, nil, recovery)
		if err != nil {
			t.Fatalf("manifest recipients %s: %v", id, err)
		}
		ct, _, err := EncodeManifest(ManifestFile{Body: signed, Recipients: recipients}, agebox.X25519RecipientProvider{Strings: recipients})
		if err != nil {
			t.Fatalf("encode manifest %s: %v", id, err)
		}
		writeTestObject(t, dir, id, ct)
	}

	root := StoreRoot{
		Schema: Schema, StoreID: "ks_walkteststore123", CreatedAt: "2026-07-28T00:00:00Z",
		Format: DefaultStoreFormat(), RootNodeID: "n_walkroot12345678",
		TrustAnchors: []TrustAnchor{{IID: "i_walkowner1234567", SignPubkey: ownerSignPub}},
	}

	return &testStore{
		dir: dir, root: root,
		ownerSigner: ownerSigner, ownerSignPub: ownerSignPub,
		ownerIP: ownerIP, readerIP: readerIP, recoveryIP: recoveryIP,
		tree: tree, index: index, secret: secret,
	}
}

func writeTestObject(t *testing.T, dir, id string, ct []byte) {
	t.Helper()
	if err := os.WriteFile(ObjectPath(dir, id), ct, 0o600); err != nil {
		t.Fatalf("write %s: %v", id, err)
	}
}

func emptyPins() *Pins {
	return &Pins{Schema: pinsSchema, NodeVersions: map[string]int{}}
}

func TestWalkSpineHappyPath(t *testing.T) {
	ts := buildTestStore(t)
	pins := emptyPins()
	res, err := WalkSpine(ts.dir, ts.root, pins, ts.ownerIP, bundle.Ed25519Verifier{}, []string{"aws", "profile"})
	if err != nil {
		t.Fatalf("WalkSpine: %v", err)
	}
	if len(res.SpineIDs) != 3 {
		t.Fatalf("spine = %v", res.SpineIDs)
	}
	leaf := res.Nodes["n_walkprofile123456"]
	ix, err := LoadIndex(ts.dir, leaf.Body, ts.ownerIP)
	if err != nil {
		t.Fatalf("LoadIndex: %v", err)
	}
	obj, err := LoadObject(ts.dir, ix.Entries["amzn-wanfe"], ts.ownerIP)
	if err != nil {
		t.Fatalf("LoadObject: %v", err)
	}
	content, err := base64.StdEncoding.DecodeString(obj.ContentBase64)
	if err != nil {
		t.Fatalf("decode content: %v", err)
	}
	if string(content) != string(ts.secret) {
		t.Fatalf("content mismatch")
	}
	if pins.NodeVersions["n_walkprofile123456"] != 1 || pins.NodeVersions["n_walkroot12345678"] != 1 {
		t.Fatalf("pins not advanced: %v", pins.NodeVersions)
	}
}

func TestWalkSpineAsReader(t *testing.T) {
	ts := buildTestStore(t)
	res, err := WalkSpine(ts.dir, ts.root, emptyPins(), ts.readerIP, bundle.Ed25519Verifier{}, []string{"aws", "profile"})
	if err != nil {
		t.Fatalf("WalkSpine as reader: %v", err)
	}
	leaf := res.Nodes["n_walkprofile123456"]
	ix, err := LoadIndex(ts.dir, leaf.Body, ts.readerIP)
	if err != nil {
		t.Fatalf("LoadIndex as reader: %v", err)
	}
	if _, err := LoadObject(ts.dir, ix.Entries["amzn-wanfe"], ts.readerIP); err != nil {
		t.Fatalf("LoadObject as reader: %v", err)
	}
}

func TestWalkSpineRecoveryReadsEverything(t *testing.T) {
	ts := buildTestStore(t)
	res, err := WalkSpine(ts.dir, ts.root, emptyPins(), ts.recoveryIP, bundle.Ed25519Verifier{}, []string{"aws", "profile"})
	if err != nil {
		t.Fatalf("WalkSpine as recovery: %v", err)
	}
	leaf := res.Nodes["n_walkprofile123456"]
	ix, err := LoadIndex(ts.dir, leaf.Body, ts.recoveryIP)
	if err != nil {
		t.Fatalf("LoadIndex as recovery: %v", err)
	}
	if _, err := LoadObject(ts.dir, ix.Entries["amzn-wanfe"], ts.recoveryIP); err != nil {
		t.Fatalf("LoadObject as recovery: %v", err)
	}
}

func TestWalkForgedRootSigner(t *testing.T) {
	ts := buildTestStore(t)
	attackerSigner, attackerPub := newTestSigner(t)
	_ = attackerPub
	body := ts.tree["n_walkroot12345678"]
	forged, err := SignBody(body, attackerSigner)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	recipients, _ := RecipientSet(ArtifactManifest, body.NodeID, "", ts.tree, nil, nil)
	ct, _, err := EncodeManifest(ManifestFile{Body: forged, Recipients: recipients}, agebox.X25519RecipientProvider{Strings: recipients})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	writeTestObject(t, ts.dir, body.NodeID, ct)

	_, err = WalkSpine(ts.dir, ts.root, emptyPins(), ts.ownerIP, bundle.Ed25519Verifier{}, nil)
	if !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("err = %v, want ErrUntrustedSigner", err)
	}
}

func TestWalkUnattestedChild(t *testing.T) {
	ts := buildTestStore(t)
	attackerSigner, _ := newTestSigner(t)
	body := ts.tree["n_walkaws123456789"]
	forged, err := SignBody(body, attackerSigner)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	recipients, _ := RecipientSet(ArtifactManifest, body.NodeID, "", ts.tree, nil, nil)
	ct, _, err := EncodeManifest(ManifestFile{Body: forged, Recipients: recipients}, agebox.X25519RecipientProvider{Strings: recipients})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	writeTestObject(t, ts.dir, body.NodeID, ct)

	_, err = WalkSpine(ts.dir, ts.root, emptyPins(), ts.ownerIP, bundle.Ed25519Verifier{}, []string{"aws"})
	if !errors.Is(err, ErrUnattestedChild) {
		t.Fatalf("err = %v, want ErrUnattestedChild", err)
	}
}

func TestWalkVersionRollback(t *testing.T) {
	ts := buildTestStore(t)
	pins := emptyPins()
	pins.NodeVersions["n_walkroot12345678"] = 5
	_, err := WalkSpine(ts.dir, ts.root, pins, ts.ownerIP, bundle.Ed25519Verifier{}, nil)
	if !errors.Is(err, ErrRollback) {
		t.Fatalf("err = %v, want ErrRollback", err)
	}
}

func TestWalkIndexHashMismatch(t *testing.T) {
	ts := buildTestStore(t)
	tampered := ts.index
	tampered.Entries = map[string]IndexEntry{}
	recipients, _ := RecipientSet(ArtifactIndex, "n_walkprofile123456", "", ts.tree, nil, nil)
	ct, _, err := EncodeIndex(tampered, agebox.X25519RecipientProvider{Strings: recipients})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	writeTestObject(t, ts.dir, "x_walkindex1234567", ct)

	res, err := WalkSpine(ts.dir, ts.root, emptyPins(), ts.ownerIP, bundle.Ed25519Verifier{}, []string{"aws", "profile"})
	if err != nil {
		t.Fatalf("WalkSpine: %v", err)
	}
	_, err = LoadIndex(ts.dir, res.Nodes["n_walkprofile123456"].Body, ts.ownerIP)
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("err = %v, want ErrHashMismatch", err)
	}
}

func TestWalkObjectHashMismatch(t *testing.T) {
	ts := buildTestStore(t)
	tampered := Object{
		Schema: Schema, Kind: "file", StoreID: ts.root.StoreID,
		ObjectID:      "o_walkobject1234567",
		ContentBase64: base64.StdEncoding.EncodeToString([]byte("EVIL")),
		SHA256:        shaHex([]byte("EVIL")),
		CreatedAt:     "2026-07-28T00:00:00Z", UpdatedAt: "2026-07-28T00:00:00Z",
	}
	recipients, _ := RecipientSet(ArtifactIndex, "n_walkprofile123456", "", ts.tree, nil, nil)
	ct, _, err := EncodeObject(tampered, agebox.X25519RecipientProvider{Strings: recipients})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	writeTestObject(t, ts.dir, "o_walkobject1234567", ct)

	res, err := WalkSpine(ts.dir, ts.root, emptyPins(), ts.ownerIP, bundle.Ed25519Verifier{}, []string{"aws", "profile"})
	if err != nil {
		t.Fatalf("WalkSpine: %v", err)
	}
	ix, err := LoadIndex(ts.dir, res.Nodes["n_walkprofile123456"].Body, ts.ownerIP)
	if err != nil {
		t.Fatalf("LoadIndex: %v", err)
	}
	_, err = LoadObject(ts.dir, ix.Entries["amzn-wanfe"], ts.ownerIP)
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("err = %v, want ErrHashMismatch", err)
	}
}

func TestWalkStoreIDMismatch(t *testing.T) {
	ts := buildTestStore(t)
	root := ts.root
	root.StoreID = "ks_othersstore12345"
	_, err := WalkSpine(ts.dir, root, emptyPins(), ts.ownerIP, bundle.Ed25519Verifier{}, nil)
	if !errors.Is(err, ErrStoreIDMismatch) {
		t.Fatalf("err = %v, want ErrStoreIDMismatch", err)
	}
}

func TestWalkPathNotFound(t *testing.T) {
	ts := buildTestStore(t)
	_, err := WalkSpine(ts.dir, ts.root, emptyPins(), ts.ownerIP, bundle.Ed25519Verifier{}, []string{"nosuch"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestLoadReadableTree(t *testing.T) {
	ts := buildTestStore(t)
	nodes, err := LoadReadableTree(ts.dir, ts.root, emptyPins(), ts.ownerIP, bundle.Ed25519Verifier{})
	if err != nil {
		t.Fatalf("LoadReadableTree: %v", err)
	}
	if len(nodes) != 3 {
		t.Fatalf("nodes = %d, want 3", len(nodes))
	}
}
