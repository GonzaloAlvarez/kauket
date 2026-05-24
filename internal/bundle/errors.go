package bundle

import "errors"

var (
	ErrUnknownHost      = errors.New("unknown host")
	ErrUnsignedRequest  = errors.New("request has no signature")
	ErrInvalidSignature = errors.New("invalid request signature")
)
