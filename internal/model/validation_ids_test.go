package model

import "testing"

func TestValidateIdentityID(t *testing.T) {
	valid := []string{"h_abcdefghijklmnop", "i_aaaaaaaaaaaaaaaa", "h_a2z4567abcdefghi"}
	for _, id := range valid {
		if err := ValidateIdentityID(id); err != nil {
			t.Fatalf("ValidateIdentityID(%q) = %v, want nil", id, err)
		}
	}
	invalid := []string{
		"", "h_", "i_short", "x_abcdefghijklmnop",
		"../../etc/passwd", "h_abcdefghijklmno/", "h_ABCDEFGHIJKLMNOP",
		"h_abcdefghijklmno1", "h_abcdefghijklmnopq",
	}
	for _, id := range invalid {
		if err := ValidateIdentityID(id); err == nil {
			t.Fatalf("ValidateIdentityID(%q) = nil, want error", id)
		}
	}
}

func TestValidateRequestID(t *testing.T) {
	if err := ValidateRequestID("rq_abcdefghijklmnop"); err != nil {
		t.Fatalf("valid request id rejected: %v", err)
	}
	for _, id := range []string{"", "rq_short", "h_abcdefghijklmnop", "rq_../../evil1234"} {
		if err := ValidateRequestID(id); err == nil {
			t.Fatalf("ValidateRequestID(%q) = nil, want error", id)
		}
	}
}

func TestGeneratedIDsPassValidation(t *testing.T) {
	if err := ValidateIdentityID(NewHostID()); err != nil {
		t.Fatalf("generated host id rejected: %v", err)
	}
	if err := ValidateIdentityID(NewIdentityID()); err != nil {
		t.Fatalf("generated identity id rejected: %v", err)
	}
	if err := ValidateRequestID(NewRequestID()); err != nil {
		t.Fatalf("generated request id rejected: %v", err)
	}
}
