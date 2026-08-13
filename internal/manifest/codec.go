package manifest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/model"
	"golang.org/x/crypto/ssh"
)

func shaHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func SignBody(body ManifestBody, signer bundle.Signer) (ManifestBody, error) {
	body.Signature = nil
	payload, err := model.MarshalCanonical(body)
	if err != nil {
		return ManifestBody{}, fmt.Errorf("kauket: canonicalize manifest: %w", err)
	}
	sig, fpr, err := signer.Sign(payload)
	if err != nil {
		return ManifestBody{}, fmt.Errorf("kauket: sign manifest: %w", err)
	}
	body.Signature = &Signature{
		Algorithm:            "ed25519",
		PublicKeyFingerprint: fpr,
		SignatureBase64:      base64.StdEncoding.EncodeToString(sig),
	}
	return body, nil
}

func BodySHA256(body ManifestBody) (string, error) {
	canonical, err := model.MarshalCanonical(body)
	if err != nil {
		return "", fmt.Errorf("kauket: canonicalize manifest: %w", err)
	}
	return shaHex(canonical), nil
}

func EncodeManifest(f ManifestFile, rp agebox.RecipientProvider) ([]byte, string, error) {
	if f.Body.Signature == nil {
		return nil, "", ErrUnsignedManifest
	}
	bodySHA, err := BodySHA256(f.Body)
	if err != nil {
		return nil, "", err
	}
	plain, err := json.Marshal(f)
	if err != nil {
		return nil, "", fmt.Errorf("kauket: marshal manifest file: %w", err)
	}
	padded, err := agebox.WrapMeta(plain)
	if err != nil {
		return nil, "", fmt.Errorf("kauket: pad manifest: %w", err)
	}
	ct, err := agebox.Encrypt(padded, rp)
	if err != nil {
		return nil, "", fmt.Errorf("kauket: encrypt manifest: %w", err)
	}
	return ct, bodySHA, nil
}

func DecodeManifest(ct []byte, ip agebox.IdentityProvider) (ManifestFile, error) {
	padded, err := agebox.Decrypt(ct, ip)
	if err != nil {
		return ManifestFile{}, fmt.Errorf("kauket: decrypt manifest: %w", err)
	}
	plain, err := agebox.Unwrap(padded)
	if err != nil {
		return ManifestFile{}, fmt.Errorf("kauket: unwrap manifest: %w", err)
	}
	var f ManifestFile
	if err := json.Unmarshal(plain, &f); err != nil {
		return ManifestFile{}, fmt.Errorf("kauket: parse manifest: %w", err)
	}
	if !schemaSupported(f.Body.Schema) || f.Body.Kind != KindManifest {
		return ManifestFile{}, fmt.Errorf("kauket: unsupported manifest schema %d kind %q", f.Body.Schema, f.Body.Kind)
	}
	return f, nil
}

func VerifyManifest(f ManifestFile, trustedSignKeys []string, v bundle.Verifier) error {
	if f.Body.Signature == nil {
		return ErrUnsignedManifest
	}
	body := f.Body
	sig := body.Signature
	body.Signature = nil
	payload, err := model.MarshalCanonical(body)
	if err != nil {
		return fmt.Errorf("kauket: canonicalize manifest: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.SignatureBase64)
	if err != nil {
		return fmt.Errorf("kauket: decode manifest signature: %w", err)
	}
	for _, key := range trustedSignKeys {
		fpr, err := fingerprintOf(key)
		if err != nil {
			continue
		}
		if fpr != sig.PublicKeyFingerprint {
			continue
		}
		if err := v.Verify(payload, sigBytes, key); err != nil {
			return fmt.Errorf("%w: %v", ErrUntrustedSigner, err)
		}
		return nil
	}
	return ErrUntrustedSigner
}

func fingerprintOf(sshPublicKey string) (string, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshPublicKey))
	if err != nil {
		return "", fmt.Errorf("kauket: parse public key: %w", err)
	}
	return ssh.FingerprintSHA256(pub), nil
}

func SignKeyFingerprint(sshPublicKey string) (string, error) {
	return fingerprintOf(sshPublicKey)
}

func EncodeIndex(ix Index, rp agebox.RecipientProvider) ([]byte, string, error) {
	canonical, err := model.MarshalCanonical(ix)
	if err != nil {
		return nil, "", fmt.Errorf("kauket: canonicalize index: %w", err)
	}
	padded, err := agebox.WrapMeta(canonical)
	if err != nil {
		return nil, "", fmt.Errorf("kauket: pad index: %w", err)
	}
	ct, err := agebox.Encrypt(padded, rp)
	if err != nil {
		return nil, "", fmt.Errorf("kauket: encrypt index: %w", err)
	}
	return ct, shaHex(canonical), nil
}

func DecodeIndex(ct []byte, ip agebox.IdentityProvider, wantSHA string) (Index, error) {
	padded, err := agebox.Decrypt(ct, ip)
	if err != nil {
		return Index{}, fmt.Errorf("kauket: decrypt index: %w", err)
	}
	plain, err := agebox.Unwrap(padded)
	if err != nil {
		return Index{}, fmt.Errorf("kauket: unwrap index: %w", err)
	}
	if shaHex(plain) != wantSHA {
		return Index{}, fmt.Errorf("%w: index", ErrHashMismatch)
	}
	var ix Index
	if err := json.Unmarshal(plain, &ix); err != nil {
		return Index{}, fmt.Errorf("kauket: parse index: %w", err)
	}
	if !schemaSupported(ix.Schema) || ix.Kind != KindIndex {
		return Index{}, fmt.Errorf("kauket: unsupported index schema %d kind %q", ix.Schema, ix.Kind)
	}
	if ix.Entries == nil {
		ix.Entries = map[string]IndexEntry{}
	}
	return ix, nil
}

func EncodeObject(o Object, rp agebox.RecipientProvider) ([]byte, string, error) {
	canonical, err := model.MarshalCanonical(o)
	if err != nil {
		return nil, "", fmt.Errorf("kauket: canonicalize object: %w", err)
	}
	padded, err := agebox.Wrap(canonical, 0)
	if err != nil {
		return nil, "", fmt.Errorf("kauket: pad object: %w", err)
	}
	ct, err := agebox.Encrypt(padded, rp)
	if err != nil {
		return nil, "", fmt.Errorf("kauket: encrypt object: %w", err)
	}
	return ct, shaHex(canonical), nil
}

func DecodeObject(ct []byte, ip agebox.IdentityProvider, wantSHA string) (Object, error) {
	padded, err := agebox.Decrypt(ct, ip)
	if err != nil {
		return Object{}, fmt.Errorf("kauket: decrypt object: %w", err)
	}
	plain, err := agebox.Unwrap(padded)
	if err != nil {
		return Object{}, fmt.Errorf("kauket: unwrap object: %w", err)
	}
	if shaHex(plain) != wantSHA {
		return Object{}, fmt.Errorf("%w: object", ErrHashMismatch)
	}
	var o Object
	if err := json.Unmarshal(plain, &o); err != nil {
		return Object{}, fmt.Errorf("kauket: parse object: %w", err)
	}
	if !schemaSupported(o.Schema) {
		return Object{}, fmt.Errorf("kauket: unsupported object schema %d", o.Schema)
	}
	return o, nil
}

func EncodeRoutedRequest(rr RoutedRequest, rp agebox.RecipientProvider) ([]byte, error) {
	canonical, err := model.MarshalCanonical(rr)
	if err != nil {
		return nil, fmt.Errorf("kauket: canonicalize routed request: %w", err)
	}
	padded, err := agebox.WrapMeta(canonical)
	if err != nil {
		return nil, fmt.Errorf("kauket: pad routed request: %w", err)
	}
	ct, err := agebox.Encrypt(padded, rp)
	if err != nil {
		return nil, fmt.Errorf("kauket: encrypt routed request: %w", err)
	}
	return ct, nil
}

func DecodeRoutedRequest(ct []byte, ip agebox.IdentityProvider) (RoutedRequest, error) {
	padded, err := agebox.Decrypt(ct, ip)
	if err != nil {
		return RoutedRequest{}, fmt.Errorf("kauket: decrypt routed request: %w", err)
	}
	plain, err := agebox.Unwrap(padded)
	if err != nil {
		return RoutedRequest{}, fmt.Errorf("kauket: unwrap routed request: %w", err)
	}
	var rr RoutedRequest
	if err := json.Unmarshal(plain, &rr); err != nil {
		return RoutedRequest{}, fmt.Errorf("kauket: parse routed request: %w", err)
	}
	if !schemaSupported(rr.Schema) || rr.Kind != KindRoutedRequest {
		return RoutedRequest{}, fmt.Errorf("kauket: unsupported routed request schema %d kind %q", rr.Schema, rr.Kind)
	}
	return rr, nil
}

func SignStoreRoot(root StoreRoot, signer bundle.Signer) ([]byte, []byte, error) {
	doc, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("kauket: marshal store root: %w", err)
	}
	doc = append(doc, '\n')
	canonical, err := model.MarshalCanonical(root)
	if err != nil {
		return nil, nil, fmt.Errorf("kauket: canonicalize store root: %w", err)
	}
	sigBytes, fpr, err := signer.Sign(canonical)
	if err != nil {
		return nil, nil, fmt.Errorf("kauket: sign store root: %w", err)
	}
	sigDoc, err := json.MarshalIndent(Signature{
		Algorithm:            "ed25519",
		PublicKeyFingerprint: fpr,
		SignatureBase64:      base64.StdEncoding.EncodeToString(sigBytes),
	}, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("kauket: marshal store root signature: %w", err)
	}
	sigDoc = append(sigDoc, '\n')
	return doc, sigDoc, nil
}

func VerifyStoreRoot(doc, sigDoc []byte, pinnedSignKeys []string, v bundle.Verifier) (StoreRoot, string, error) {
	var root StoreRoot
	if err := json.Unmarshal(doc, &root); err != nil {
		return StoreRoot{}, "", fmt.Errorf("kauket: parse store.json: %w", err)
	}
	if !schemaSupported(root.Schema) {
		return StoreRoot{}, "", fmt.Errorf("kauket: unsupported store schema %d", root.Schema)
	}
	var sig Signature
	if err := json.Unmarshal(sigDoc, &sig); err != nil {
		return StoreRoot{}, "", fmt.Errorf("kauket: parse store.json.sig: %w", err)
	}
	canonical, err := model.MarshalCanonical(root)
	if err != nil {
		return StoreRoot{}, "", fmt.Errorf("kauket: canonicalize store root: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.SignatureBase64)
	if err != nil {
		return StoreRoot{}, "", fmt.Errorf("kauket: decode store root signature: %w", err)
	}
	for _, key := range pinnedSignKeys {
		fpr, err := fingerprintOf(key)
		if err != nil {
			continue
		}
		if fpr != sig.PublicKeyFingerprint {
			continue
		}
		if err := v.Verify(canonical, sigBytes, key); err != nil {
			return StoreRoot{}, "", fmt.Errorf("%w: %v", ErrUntrustedSigner, err)
		}
		return root, key, nil
	}
	return StoreRoot{}, "", ErrUntrustedSigner
}
