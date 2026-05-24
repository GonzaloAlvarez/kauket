package model

import "testing"

func TestValidateSecretID(t *testing.T) {
	cases := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"ssh.main_private_key", "ssh.main_private_key", false},
		{"aws.primary_account.key_file", "aws.primary_account.key_file", false},
		{"cloudflare.dns_api_token", "cloudflare.dns_api_token", false},
		{"slash separator", "ssh/main_private_key", true},
		{"traversal prefix", "../ssh.main_private_key", true},
		{"double dot", "ssh..main", true},
		{"uppercase prefix", "SSH.main", true},
		{"hyphen segment", "ssh.main-private-key", true},
		{"space segment", "ssh main", true},
		{"empty", "", true},
		{"single segment", "ssh", true},
		{"starts with number", "1ssh.foo", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSecretID(tc.id)
			gotErr := err != nil
			if gotErr != tc.wantErr {
				t.Fatalf("ValidateSecretID(%q) error = %v, wantErr = %v", tc.id, err, tc.wantErr)
			}
			if gotErr {
				want := "secret id \"" + tc.id + "\" is invalid"
				if err.Error() != want {
					t.Fatalf("error message = %q, want %q", err.Error(), want)
				}
			}
		})
	}
}
