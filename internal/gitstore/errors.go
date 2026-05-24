package gitstore

import "errors"

var (
	ErrLocked         = errors.New("kauket: gitstore lock is held by another process")
	ErrNonFastForward = errors.New("kauket: push rejected as non-fast-forward")
	ErrNoRequestFile  = errors.New("kauket: request branch tree is missing requests/<id>.age")
)
