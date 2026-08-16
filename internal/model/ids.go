package model

import (
	"crypto/rand"
	"encoding/base32"
)

var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func randomID(prefix string) string {
	var buf [10]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic(err)
	}
	return prefix + idEncoding.EncodeToString(buf[:])
}

func NewStoreID() string {
	return randomID("ks_")
}

func NewHostID() string {
	return randomID("h_")
}

func NewRequestID() string {
	return randomID("rq_")
}

func NewNodeID() string {
	return randomID("n_")
}

func NewIndexObjectID() string {
	return randomID("x_")
}

func NewObjectID() string {
	return randomID("o_")
}

func NewRoutedRequestID() string {
	return randomID("r_")
}

func NewIdentityID() string {
	return randomID("i_")
}
