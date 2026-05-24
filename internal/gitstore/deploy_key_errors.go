package gitstore

import "errors"

var (
	ErrInvalidHostID    = errors.New("kauket: invalid host id")
	ErrInvalidPublicKey = errors.New("kauket: invalid public key")
)
