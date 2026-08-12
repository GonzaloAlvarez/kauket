package manifest

import "errors"

var (
	ErrUntrustedSigner  = errors.New("kauket: signer is not in the trusted key set")
	ErrUnattestedChild  = errors.New("kauket: child manifest signer is not attested by its parent")
	ErrRollback         = errors.New("kauket: manifest version is older than the pinned version")
	ErrHashMismatch     = errors.New("kauket: content hash does not match its signed binding")
	ErrStoreIDMismatch  = errors.New("kauket: store id does not match the pinned store")
	ErrExists           = errors.New("kauket: secret already exists")
	ErrNotFound         = errors.New("kauket: path not found")
	ErrNotOwner         = errors.New("kauket: identity is not an owner of this node")
	ErrUnsignedManifest = errors.New("kauket: manifest has no signature")
)
