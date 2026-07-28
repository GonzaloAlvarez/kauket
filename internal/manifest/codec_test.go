package manifest

import (
	"errors"
	"strings"
	"testing"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
)

func TestManifestSignEncodeDecodeVerifyRoundtrip(t *testing.T) {
	signer, signPub := newTestSigner(t)
	_, ip, recipient := newTestAgeIdentity(t)

	signed, err := SignBody(fixtureBody(), signer)
	if err != nil {
		t.Fatalf("SignBody: %v", err)
	}
	if signed.Signature == nil || signed.Signature.Algorithm != "ed25519" {
		t.Fatalf("signature = %+v", signed.Signature)
	}

	f := ManifestFile{Body: signed, Recipients: []string{recipient}}
	ct, bodySHA, err := EncodeManifest(f, agebox.X25519RecipientProvider{Strings: []string{recipient}})
	if err != nil {
		t.Fatalf("EncodeManifest: %v", err)
	}
	if bodySHA == "" {
		t.Fatalf("empty body sha")
	}

	got, err := DecodeManifest(ct, ip)
	if err != nil {
		t.Fatalf("DecodeManifest: %v", err)
	}
	if got.Body.NodeID != signed.NodeID || got.Body.Version != signed.Version {
		t.Fatalf("decoded body mismatch: %+v", got.Body)
	}
	if len(got.Recipients) != 1 || got.Recipients[0] != recipient {
		t.Fatalf("recipients cache mismatch: %v", got.Recipients)
	}

	if err := VerifyManifest(got, []string{signPub}, bundle.Ed25519Verifier{}); err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}

	gotSHA, err := BodySHA256(got.Body)
	if err != nil {
		t.Fatalf("BodySHA256: %v", err)
	}
	if gotSHA != bodySHA {
		t.Fatalf("body sha mismatch after roundtrip: %s != %s", gotSHA, bodySHA)
	}
}

func TestVerifyManifestForgedSigner(t *testing.T) {
	signer, _ := newTestSigner(t)
	_, otherPub := newTestSigner(t)

	signed, err := SignBody(fixtureBody(), signer)
	if err != nil {
		t.Fatalf("SignBody: %v", err)
	}
	f := ManifestFile{Body: signed}
	err = VerifyManifest(f, []string{otherPub}, bundle.Ed25519Verifier{})
	if !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("err = %v, want ErrUntrustedSigner", err)
	}
}

func TestVerifyManifestTamperedBody(t *testing.T) {
	signer, signPub := newTestSigner(t)
	signed, err := SignBody(fixtureBody(), signer)
	if err != nil {
		t.Fatalf("SignBody: %v", err)
	}
	signed.Version = 99
	err = VerifyManifest(ManifestFile{Body: signed}, []string{signPub}, bundle.Ed25519Verifier{})
	if !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("err = %v, want ErrUntrustedSigner for tampered body", err)
	}
}

func TestVerifyManifestUnsigned(t *testing.T) {
	err := VerifyManifest(ManifestFile{Body: fixtureBody()}, nil, bundle.Ed25519Verifier{})
	if !errors.Is(err, ErrUnsignedManifest) {
		t.Fatalf("err = %v, want ErrUnsignedManifest", err)
	}
}

func TestEncodeManifestRefusesUnsigned(t *testing.T) {
	_, _, recipient := newTestAgeIdentity(t)
	_, _, err := EncodeManifest(ManifestFile{Body: fixtureBody()}, agebox.X25519RecipientProvider{Strings: []string{recipient}})
	if !errors.Is(err, ErrUnsignedManifest) {
		t.Fatalf("err = %v, want ErrUnsignedManifest", err)
	}
}

func TestIndexRoundtripAndHashBinding(t *testing.T) {
	_, ip, recipient := newTestAgeIdentity(t)
	ct, sha, err := EncodeIndex(fixtureIndex(), agebox.X25519RecipientProvider{Strings: []string{recipient}})
	if err != nil {
		t.Fatalf("EncodeIndex: %v", err)
	}
	ix, err := DecodeIndex(ct, ip, sha)
	if err != nil {
		t.Fatalf("DecodeIndex: %v", err)
	}
	if _, ok := ix.Entries["amzn-wanfe"]; !ok {
		t.Fatalf("entries = %v", ix.Entries)
	}
	if _, err := DecodeIndex(ct, ip, strings.Repeat("f", 64)); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("wrong sha: err = %v, want ErrHashMismatch", err)
	}
}

func TestObjectRoundtripAndHashBinding(t *testing.T) {
	_, ip, recipient := newTestAgeIdentity(t)
	ct, sha, err := EncodeObject(fixtureObject(), agebox.X25519RecipientProvider{Strings: []string{recipient}})
	if err != nil {
		t.Fatalf("EncodeObject: %v", err)
	}
	o, err := DecodeObject(ct, ip, sha)
	if err != nil {
		t.Fatalf("DecodeObject: %v", err)
	}
	if o.ObjectID != "o_fixtureobject1234" || o.Kind != "file" {
		t.Fatalf("object = %+v", o)
	}
	if _, err := DecodeObject(ct, ip, strings.Repeat("f", 64)); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("wrong sha: err = %v, want ErrHashMismatch", err)
	}
}

func TestStoreRootSignVerifyRoundtrip(t *testing.T) {
	signer, signPub := newTestSigner(t)
	doc, sig, err := SignStoreRoot(fixtureStoreRoot(), signer)
	if err != nil {
		t.Fatalf("SignStoreRoot: %v", err)
	}
	root, err := VerifyStoreRoot(doc, sig, []string{signPub}, bundle.Ed25519Verifier{})
	if err != nil {
		t.Fatalf("VerifyStoreRoot: %v", err)
	}
	if root.StoreID != "ks_fixturestore1234" || root.RootNodeID != "n_fixtureroot123456" {
		t.Fatalf("root = %+v", root)
	}
}

func TestVerifyStoreRootTampered(t *testing.T) {
	signer, signPub := newTestSigner(t)
	doc, sig, err := SignStoreRoot(fixtureStoreRoot(), signer)
	if err != nil {
		t.Fatalf("SignStoreRoot: %v", err)
	}
	tampered := []byte(strings.Replace(string(doc), "GonzaloAlvarez", "attacker", 1))
	if _, err := VerifyStoreRoot(tampered, sig, []string{signPub}, bundle.Ed25519Verifier{}); !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("tampered doc: err = %v, want ErrUntrustedSigner", err)
	}
	_, otherPub := newTestSigner(t)
	if _, err := VerifyStoreRoot(doc, sig, []string{otherPub}, bundle.Ed25519Verifier{}); !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("unpinned signer: err = %v, want ErrUntrustedSigner", err)
	}
}

func TestRoutedRequestRoundtrip(t *testing.T) {
	_, ip, recipient := newTestAgeIdentity(t)
	rr := RoutedRequest{
		Schema:       Schema,
		Kind:         KindRoutedRequest,
		StoreID:      "ks_fixturestore1234",
		RequestID:    "rq_fixturereq123456",
		RoutedBy:     "i_fixtureowner12345",
		RoutedAt:     "2026-07-28T00:00:00Z",
		TargetNodeID: "n_fixturenode123456",
	}
	ct, err := EncodeRoutedRequest(rr, agebox.X25519RecipientProvider{Strings: []string{recipient}})
	if err != nil {
		t.Fatalf("EncodeRoutedRequest: %v", err)
	}
	got, err := DecodeRoutedRequest(ct, ip)
	if err != nil {
		t.Fatalf("DecodeRoutedRequest: %v", err)
	}
	if got.RequestID != rr.RequestID || got.TargetNodeID != rr.TargetNodeID {
		t.Fatalf("routed request = %+v", got)
	}
}

func TestEncrypt128Recipients(t *testing.T) {
	id, ip, recipient := newTestAgeIdentity(t)
	_ = id
	recipients := []string{recipient}
	for i := 0; i < 127; i++ {
		extra, err := agebox.GenerateIdentity()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		recipients = append(recipients, extra.Recipient().String())
	}
	signer, _ := newTestSigner(t)
	signed, err := SignBody(fixtureBody(), signer)
	if err != nil {
		t.Fatalf("SignBody: %v", err)
	}
	ct, _, err := EncodeManifest(ManifestFile{Body: signed, Recipients: recipients}, agebox.X25519RecipientProvider{Strings: recipients})
	if err != nil {
		t.Fatalf("EncodeManifest with 128 recipients: %v", err)
	}
	if _, err := DecodeManifest(ct, ip); err != nil {
		t.Fatalf("DecodeManifest with 128 recipients: %v", err)
	}
}
