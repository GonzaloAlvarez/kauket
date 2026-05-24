package model

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestMarshalCanonicalRoundTripVault(t *testing.T) {
	v := Vault{
		Schema:    1,
		StoreID:   "ks_6me7bk1f9s4xz2qa",
		CreatedAt: "2026-05-24T00:00:00Z",
		UpdatedAt: "2026-05-24T00:00:00Z",
		Admins: []AdminRecipient{
			{ID: "ar_3m0vq2ks9p8n1c7x", Recipient: "age1aaa", CreatedAt: "2026-05-24T00:00:00Z"},
			{ID: "ar_bbbbbbbbbbbbbbbb", Recipient: "age1bbb", CreatedAt: "2026-05-24T00:00:00Z"},
		},
		Profiles: map[string]Profile{
			"ssh": {Description: "ssh profile"},
			"aws": {Description: "aws profile"},
		},
		Secrets: map[string]Secret{
			"ssh.main_private_key": {
				SecretObjectID: "s_q8x4c9vy2m7k1w0z",
				Kind:           "file",
				Profiles:       []string{"ssh"},
				Install:        InstallSpec{Destination: "~/.ssh/main_private_key", Mode: "0600", DirectoryMode: "0700"},
				ContentBase64:  "QUFBQQ==",
				SHA256:         "deadbeef",
				CreatedAt:      "2026-05-24T00:00:00Z",
				UpdatedAt:      "2026-05-24T00:00:00Z",
			},
			"aws.primary_account.key_file": {
				SecretObjectID: "s_aaaaaaaaaaaaaaaa",
				Kind:           "file",
				Profiles:       []string{"aws"},
				Install:        InstallSpec{Destination: "~/.aws/credentials", Mode: "0600", DirectoryMode: "0700"},
				ContentBase64:  "QkJCQg==",
				SHA256:         "cafebabe",
				CreatedAt:      "2026-05-24T00:00:00Z",
				UpdatedAt:      "2026-05-24T00:00:00Z",
			},
			"cloudflare.dns_api_token": {
				SecretObjectID: "s_cccccccccccccccc",
				Kind:           "file",
				Profiles:       []string{},
				Install:        InstallSpec{Destination: "~/.cf/token", Mode: "0600", DirectoryMode: "0700"},
				ContentBase64:  "Q0NDQw==",
				SHA256:         "feedface",
				CreatedAt:      "2026-05-24T00:00:00Z",
				UpdatedAt:      "2026-05-24T00:00:00Z",
			},
		},
		Hosts: map[string]Host{
			"h_7j4v6m2q9xk3p8da": {
				DisplayName:          "machine2",
				ReportedHostname:     "r730xd-debian",
				AgeRecipient:         "age1host",
				DeployKeyFingerprint: "SHA256:xxx",
				GrantedProfiles:      []string{"ssh"},
				GrantedSecrets:       []string{},
				CreatedAt:            "2026-05-24T00:00:00Z",
				ApprovedAt:           "2026-05-24T00:00:00Z",
			},
			"h_b2n8w5s6c1t9qq0r": {
				DisplayName:          "machine3",
				ReportedHostname:     "kaiser",
				AgeRecipient:         "age1host2",
				DeployKeyFingerprint: "SHA256:yyy",
				GrantedProfiles:      []string{"aws"},
				GrantedSecrets:       []string{},
				CreatedAt:            "2026-05-24T00:00:00Z",
				ApprovedAt:           "2026-05-24T00:00:00Z",
			},
		},
		Requests: map[string]RequestRecord{},
	}

	first, err := MarshalCanonical(v)
	if err != nil {
		t.Fatalf("MarshalCanonical: %v", err)
	}
	var decoded any
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	second, err := MarshalCanonical(decoded)
	if err != nil {
		t.Fatalf("MarshalCanonical second: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("round trip mismatch:\nfirst:  %s\nsecond: %s", first, second)
	}
}

func TestMarshalCanonicalDeterministicMapOrder(t *testing.T) {
	cases := []struct {
		name string
		a    map[string]any
		b    map[string]any
	}{
		{
			name: "two keys",
			a:    map[string]any{"alpha": 1, "beta": 2},
			b:    map[string]any{"beta": 2, "alpha": 1},
		},
		{
			name: "nested",
			a: map[string]any{
				"z": map[string]any{"b": 1, "a": 2},
				"a": map[string]any{"y": 3, "x": 4},
			},
			b: map[string]any{
				"a": map[string]any{"x": 4, "y": 3},
				"z": map[string]any{"a": 2, "b": 1},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			aBytes, err := MarshalCanonical(tc.a)
			if err != nil {
				t.Fatalf("MarshalCanonical(a): %v", err)
			}
			bBytes, err := MarshalCanonical(tc.b)
			if err != nil {
				t.Fatalf("MarshalCanonical(b): %v", err)
			}
			if !bytes.Equal(aBytes, bBytes) {
				t.Fatalf("not deterministic:\n a: %s\n b: %s", aBytes, bBytes)
			}
		})
	}
}

func TestMarshalCanonicalNoTrailingNewline(t *testing.T) {
	out, err := MarshalCanonical(map[string]any{"k": "v"})
	if err != nil {
		t.Fatalf("MarshalCanonical: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("empty output")
	}
	if out[len(out)-1] == '\n' {
		t.Fatalf("output has trailing newline: %q", out)
	}
}

func TestMarshalCanonicalNoHTMLEscape(t *testing.T) {
	in := map[string]any{"k": "<a>&'\"</a>"}
	out, err := MarshalCanonical(in)
	if err != nil {
		t.Fatalf("MarshalCanonical: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "\\u003c") || strings.Contains(s, "\\u003e") || strings.Contains(s, "\\u0026") {
		t.Fatalf("output contains HTML escape: %s", s)
	}
	if !strings.Contains(s, "<") || !strings.Contains(s, ">") || !strings.Contains(s, "&") {
		t.Fatalf("output missing literal <, > or &: %s", s)
	}
}

func TestMarshalCanonicalRequestOmitsSignatureWhenNil(t *testing.T) {
	r := Request{
		Schema:    1,
		StoreID:   "ks_aaaaaaaaaaaaaaaa",
		RequestID: "rq_bbbbbbbbbbbbbbbb",
		CreatedAt: "2026-05-24T00:00:00Z",
		Host: RequestHost{
			ID:                 "h_cccccccccccccccc",
			DisplayName:        "machine2",
			ReportedHostname:   "r730xd-debian",
			OS:                 "linux",
			Arch:               "amd64",
			AgeRecipient:       "age1...",
			GitDeployPublicKey: "ssh-ed25519 AAAA...",
		},
		Requested: RequestedItems{Profiles: []string{"ssh"}, Secrets: []string{}},
	}
	out, err := MarshalCanonical(r)
	if err != nil {
		t.Fatalf("MarshalCanonical: %v", err)
	}
	if strings.Contains(string(out), "signature") {
		t.Fatalf("expected signature to be omitted, got %s", out)
	}
}
