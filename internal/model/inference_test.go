package model

import (
	"errors"
	"testing"
)

func TestInferInstallSpec(t *testing.T) {
	cases := []struct {
		name     string
		secretID string
		source   string
		wantSpec InstallSpec
		wantErr  error
	}{
		{
			name:     "ssh main private key",
			secretID: "ssh.main_private_key",
			source:   "/tmp/x",
			wantSpec: InstallSpec{Destination: "~/.ssh/main_private_key", Mode: "0600", DirectoryMode: "0700"},
		},
		{
			name:     "ssh three segment private key uses last segment",
			secretID: "ssh.alt_dev.main_private_key",
			source:   "/tmp/x",
			wantSpec: InstallSpec{Destination: "~/.ssh/main_private_key", Mode: "0600", DirectoryMode: "0700"},
		},
		{
			name:     "aws primary account key file",
			secretID: "aws.primary_account.key_file",
			source:   "/tmp/x",
			wantSpec: InstallSpec{Destination: "~/.aws/credentials", Mode: "0600", DirectoryMode: "0700"},
		},
		{
			name:     "aws two segments no rule",
			secretID: "aws.something",
			source:   "/tmp/x",
			wantErr:  ErrNoDestRule,
		},
		{
			name:     "myapp kubeconfig",
			secretID: "myapp.kubeconfig",
			source:   "/tmp/x",
			wantSpec: InstallSpec{Destination: "~/.kube/config", Mode: "0600", DirectoryMode: "0700"},
		},
		{
			name:     "foo bar no rule",
			secretID: "foo.bar",
			source:   "/tmp/x",
			wantErr:  ErrNoDestRule,
		},
		{
			name:     "cloudflare dns api token no rule",
			secretID: "cloudflare.dns_api_token",
			source:   "/tmp/x",
			wantErr:  ErrNoDestRule,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := InferInstallSpec(tc.secretID, tc.source)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantSpec {
				t.Fatalf("spec = %+v, want %+v", got, tc.wantSpec)
			}
		})
	}
}

func TestInferProfile(t *testing.T) {
	cases := []struct {
		name     string
		secretID string
		want     string
	}{
		{"ssh main private key", "ssh.main_private_key", "ssh"},
		{"aws primary account", "aws.primary_account.key_file", "aws"},
		{"myapp kubeconfig", "myapp.kubeconfig", "kube"},
		{"foo bar", "foo.bar", ""},
		{"cloudflare token", "cloudflare.dns_api_token", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := InferProfile(tc.secretID)
			if got != tc.want {
				t.Fatalf("profile = %q, want %q", got, tc.want)
			}
		})
	}
}
