package awsconfig

import (
	"bytes"
	"testing"
)

func TestParseRenderRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"preamble only", "# a comment\n\n"},
		{"single section", "[profile foo]\nregion = us-west-2\n"},
		{"preamble and sections", "# top\n\n[profile foo]\nregion = us-west-2\n\n[bar]\nkey = v\n"},
		{"no trailing newline", "[foo]\nkey = v"},
		{"crlf", "[foo]\r\nkey = v\r\n\r\n[bar]\r\nother = x\r\n"},
		{"indented bracket is body", "[foo]\ns3 =\n  [not-a-header]\n  max_requests = 10\n"},
		{"malformed bracket is body", "[foo]\nkey = v\n[broken\nmore = y\n"},
		{"comments inside section", "[foo]\n# comment\nkey = v\n; another\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := Parse([]byte(tc.data), KindConfig)
			got := f.Render()
			if !bytes.Equal(got, []byte(tc.data)) {
				t.Fatalf("round trip mismatch:\n got %q\nwant %q", got, tc.data)
			}
		})
	}
}

func TestParseSections(t *testing.T) {
	data := "# preamble\n[profile foo]\nregion = us-west-2\n\n[sso-session amzn]\nsso_start_url = https://x\n"
	f := Parse([]byte(data), KindConfig)
	if f.Preamble != "# preamble\n" {
		t.Fatalf("preamble = %q", f.Preamble)
	}
	if len(f.Sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(f.Sections))
	}
	if f.Sections[0].Header != "profile foo" || f.Sections[0].Key != "foo" {
		t.Fatalf("section 0: header %q key %q", f.Sections[0].Header, f.Sections[0].Key)
	}
	if f.Sections[0].Raw != "[profile foo]\nregion = us-west-2\n\n" {
		t.Fatalf("section 0 raw = %q", f.Sections[0].Raw)
	}
	if f.Sections[1].Header != "sso-session amzn" || f.Sections[1].Key != "sso-session amzn" {
		t.Fatalf("section 1: header %q key %q", f.Sections[1].Header, f.Sections[1].Key)
	}
}

func TestSectionKey(t *testing.T) {
	cases := []struct {
		name   string
		header string
		kind   FileKind
		want   string
	}{
		{"config profile prefix", "profile foo", KindConfig, "foo"},
		{"config bare", "foo", KindConfig, "foo"},
		{"config default", "default", KindConfig, "default"},
		{"config profile default", "profile default", KindConfig, "default"},
		{"config sso-session", "sso-session amzn", KindConfig, "sso-session amzn"},
		{"config whitespace collapse", "profile   foo", KindConfig, "foo"},
		{"config padded", " profile foo ", KindConfig, "foo"},
		{"credentials verbatim", "profile foo", KindCredentials, "profile foo"},
		{"credentials bare", "amzn-wanfe", KindCredentials, "amzn-wanfe"},
		{"case sensitive", "Foo", KindConfig, "Foo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SectionKey(tc.header, tc.kind); got != tc.want {
				t.Fatalf("SectionKey(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

func TestNormalizeSection(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"already normal", "[foo]\nk = v\n", "[foo]\nk = v\n"},
		{"trailing blanks stripped", "[foo]\nk = v\n\n\n", "[foo]\nk = v\n"},
		{"missing newline added", "[foo]\nk = v", "[foo]\nk = v\n"},
		{"crlf preserved", "[foo]\r\nk = v\r\n\r\n", "[foo]\r\nk = v\r\n"},
		{"whitespace-only trailing line", "[foo]\nk = v\n   \n", "[foo]\nk = v\n"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeSection(tc.raw); got != tc.want {
				t.Fatalf("NormalizeSection(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
