package model

import (
	"regexp"
	"testing"
)

func TestIDGenerators(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		gen    func() string
	}{
		{"StoreID", "ks_", NewStoreID},
		{"HostID", "h_", NewHostID},
		{"RequestID", "rq_", NewRequestID},
		{"SecretObjectID", "s_", NewSecretObjectID},
		{"AdminRecipientID", "ar_", NewAdminRecipientID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			re := regexp.MustCompile(`^` + regexp.QuoteMeta(tc.prefix) + `[a-z2-7]{16}$`)
			wantLen := len(tc.prefix) + 16
			var prev string
			for i := 0; i < 1000; i++ {
				id := tc.gen()
				if len(id) != wantLen {
					t.Fatalf("iteration %d: length = %d, want %d (id=%q)", i, len(id), wantLen, id)
				}
				if !re.MatchString(id) {
					t.Fatalf("iteration %d: id %q does not match %s", i, id, re)
				}
				if id == prev {
					t.Fatalf("iteration %d: consecutive duplicate id %q", i, id)
				}
				prev = id
			}
		})
	}
}
