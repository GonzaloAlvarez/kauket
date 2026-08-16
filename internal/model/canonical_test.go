package model

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestMarshalCanonicalRoundTripNestedDocument(t *testing.T) {
	v := map[string]any{
		"schema":     1,
		"store_id":   "ks_6me7bk1f9s4xz2qa",
		"created_at": "2026-05-24T00:00:00Z",
		"admins": []map[string]any{
			{"id": "ar_3m0vq2ks9p8n1c7x", "recipient": "age1aaa"},
			{"id": "ar_bbbbbbbbbbbbbbbb", "recipient": "age1bbb"},
		},
		"secrets": map[string]any{
			"ssh.main_private_key": map[string]any{
				"kind":           "file",
				"install":        map[string]any{"destination": "~/.ssh/main_private_key", "mode": "0600", "directory_mode": "0700"},
				"content_base64": "QUFBQQ==",
				"sha256":         "deadbeef",
			},
			"aws.primary_account.key_file": map[string]any{
				"kind":           "file",
				"install":        map[string]any{"destination": "~/.aws/credentials", "mode": "0600", "directory_mode": "0700"},
				"content_base64": "QkJCQg==",
				"sha256":         "cafebabe",
			},
		},
		"hosts": map[string]any{
			"h_7j4v6m2q9xk3p8da": map[string]any{"display_name": "machine2", "age_recipient": "age1host", "granted": []string{"ssh"}},
			"h_b2n8w5s6c1t9qq0r": map[string]any{"display_name": "machine3", "age_recipient": "age1host2", "granted": []string{"aws"}},
		},
		"requests": map[string]any{},
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
