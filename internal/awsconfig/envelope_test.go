package awsconfig

import (
	"strings"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	in := Envelope{Schema: EnvelopeSchema, Profile: "amzn-wanfe", Config: "[profile amzn-wanfe]\nregion = us-west-2\n"}
	data, err := in.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := ParseEnvelope(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out != in {
		t.Fatalf("round trip mismatch: %+v != %+v", out, in)
	}
}

func TestParseEnvelopeErrors(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{"malformed", "{not json", "malformed aws profile envelope"},
		{"wrong schema", `{"schema":2,"profile":"x","config":"[x]\n"}`, "unsupported aws profile envelope schema 2"},
		{"missing profile", `{"schema":1,"config":"[x]\n"}`, "missing profile name"},
		{"no content", `{"schema":1,"profile":"x"}`, "no config or credentials content"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseEnvelope([]byte(tc.data))
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}
