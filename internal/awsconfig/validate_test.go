package awsconfig

import "testing"

func TestValidateEnvelopeAcceptsMatchingProfile(t *testing.T) {
	env := Envelope{
		Schema:      EnvelopeSchema,
		Profile:     "amzn-wanfe",
		Config:      "[profile amzn-wanfe]\nregion = us-east-1\noutput = json\n",
		Credentials: "[amzn-wanfe]\naws_access_key_id = AKIA\naws_secret_access_key = zzz\n",
	}
	if err := ValidateEnvelope(env, nil); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
}

func TestValidateEnvelopeAcceptsSSOSession(t *testing.T) {
	env := Envelope{
		Schema:  EnvelopeSchema,
		Profile: "amzn-wanfe",
		Config: "[profile amzn-wanfe]\nsso_session = my-sso\nsso_account_id = 111\nsso_role_name = ReadOnly\nregion = us-east-1\n" +
			"[sso-session my-sso]\nsso_start_url = https://example.awsapps.com/start\nsso_region = us-east-1\n",
	}
	if err := ValidateEnvelope(env, nil); err != nil {
		t.Fatalf("SSO envelope rejected: %v", err)
	}
}

func TestValidateEnvelopeRejectsCredentialProcess(t *testing.T) {
	env := Envelope{
		Schema:  EnvelopeSchema,
		Profile: "amzn-wanfe",
		Config:  "[profile amzn-wanfe]\ncredential_process = /tmp/evil.sh\n",
	}
	if err := ValidateEnvelope(env, nil); err == nil {
		t.Fatalf("credential_process envelope accepted")
	}
}

func TestValidateEnvelopeRejectsForeignSection(t *testing.T) {
	env := Envelope{
		Schema:  EnvelopeSchema,
		Profile: "amzn-wanfe",
		Config:  "[profile amzn-wanfe]\nregion = us-east-1\n[default]\ncredential_process = /tmp/evil.sh\n",
	}
	if err := ValidateEnvelope(env, nil); err == nil {
		t.Fatalf("foreign [default] section accepted")
	}
}

func TestValidateEnvelopeRejectsMismatchedCredentials(t *testing.T) {
	env := Envelope{
		Schema:      EnvelopeSchema,
		Profile:     "amzn-wanfe",
		Credentials: "[other]\naws_access_key_id = AKIA\n",
	}
	if err := ValidateEnvelope(env, nil); err == nil {
		t.Fatalf("mismatched credentials section accepted")
	}
}
