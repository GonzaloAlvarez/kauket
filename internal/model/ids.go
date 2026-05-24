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

func NewSecretObjectID() string {
	return randomID("s_")
}

func NewAdminRecipientID() string {
	return randomID("ar_")
}
