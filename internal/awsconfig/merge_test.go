package awsconfig

import (
	"strings"
	"testing"
)

const incomingProfile = "[profile amzn-wanfe]\nregion = us-west-2\nsso_session = amzn\n"

func TestMergeIntoEmptyFile(t *testing.T) {
	res, err := Merge(nil, incomingProfile, KindConfig)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !res.Changed {
		t.Fatalf("expected Changed")
	}
	if string(res.Output) != incomingProfile {
		t.Fatalf("output = %q", res.Output)
	}
	if len(res.Sections) != 1 || res.Sections[0].Existing {
		t.Fatalf("sections = %+v", res.Sections)
	}
}

func TestMergeAppendsAfterUnrelated(t *testing.T) {
	existing := "[profile personal]\nregion = us-east-1\n"
	res, err := Merge([]byte(existing), incomingProfile, KindConfig)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	want := "[profile personal]\nregion = us-east-1\n\n" + incomingProfile
	if string(res.Output) != want {
		t.Fatalf("output:\n got %q\nwant %q", res.Output, want)
	}
}

func TestMergeAppendsToFileWithoutTrailingNewline(t *testing.T) {
	existing := "[profile personal]\nregion = us-east-1"
	res, err := Merge([]byte(existing), incomingProfile, KindConfig)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	want := "[profile personal]\nregion = us-east-1\n\n" + incomingProfile
	if string(res.Output) != want {
		t.Fatalf("output:\n got %q\nwant %q", res.Output, want)
	}
}

func TestMergeReplacesPreservingOthers(t *testing.T) {
	existing := "# keep this comment\n[profile amzn-wanfe]\nregion = eu-west-1\n\n[profile personal]\n# inner comment\nregion = us-east-1\n"
	res, err := Merge([]byte(existing), incomingProfile, KindConfig)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	out := string(res.Output)
	if !strings.HasPrefix(out, "# keep this comment\n[profile amzn-wanfe]\nregion = us-west-2\nsso_session = amzn\n\n") {
		t.Fatalf("replaced section wrong: %q", out)
	}
	if !strings.HasSuffix(out, "[profile personal]\n# inner comment\nregion = us-east-1\n") {
		t.Fatalf("unrelated section not preserved: %q", out)
	}
	if len(res.Sections) != 1 {
		t.Fatalf("sections = %+v", res.Sections)
	}
	p := res.Sections[0]
	if !p.Existing || !p.Differs || p.ExistingSHA256 == "" {
		t.Fatalf("plan = %+v", p)
	}
}

func TestMergeHeaderSpellingEquivalence(t *testing.T) {
	existing := "[amzn-wanfe]\nregion = eu-west-1\n"
	res, err := Merge([]byte(existing), incomingProfile, KindConfig)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !strings.Contains(string(res.Output), "[profile amzn-wanfe]\nregion = us-west-2") {
		t.Fatalf("bare header not replaced by incoming: %q", res.Output)
	}
	if strings.Count(string(res.Output), "amzn-wanfe]") != 1 {
		t.Fatalf("expected single section: %q", res.Output)
	}
}

func TestMergeDropsDuplicates(t *testing.T) {
	existing := "[amzn-wanfe]\nold = 1\n\n[other]\nk = v\n\n[amzn-wanfe]\nolder = 2\n"
	res, err := Merge([]byte(existing), "[amzn-wanfe]\nnew = 3\n", KindCredentials)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	out := string(res.Output)
	if strings.Count(out, "[amzn-wanfe]") != 1 {
		t.Fatalf("duplicates not dropped: %q", out)
	}
	if !strings.Contains(out, "[other]\nk = v\n") {
		t.Fatalf("unrelated section lost: %q", out)
	}
	if res.Sections[0].Duplicates != 1 {
		t.Fatalf("duplicates = %d, want 1", res.Sections[0].Duplicates)
	}
}

func TestMergeMultipleIncomingSections(t *testing.T) {
	incoming := incomingProfile + "\n[sso-session amzn]\nsso_start_url = https://x\n"
	existing := "[profile personal]\nregion = us-east-1\n"
	res, err := Merge([]byte(existing), incoming, KindConfig)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	out := string(res.Output)
	if !strings.Contains(out, "[profile amzn-wanfe]") || !strings.Contains(out, "[sso-session amzn]") {
		t.Fatalf("missing sections: %q", out)
	}
	if len(res.Sections) != 2 {
		t.Fatalf("plans = %+v", res.Sections)
	}
}

func TestMergeIdempotent(t *testing.T) {
	cases := []struct {
		name     string
		existing string
		incoming string
	}{
		{"append", "[profile personal]\nregion = us-east-1\n", incomingProfile},
		{"replace", "[profile amzn-wanfe]\nregion = eu-west-1\n\n[x]\nk = v\n", incomingProfile},
		{"empty", "", incomingProfile + "\n[sso-session amzn]\nurl = y\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, err := Merge([]byte(tc.existing), tc.incoming, KindConfig)
			if err != nil {
				t.Fatalf("first merge: %v", err)
			}
			second, err := Merge(first.Output, tc.incoming, KindConfig)
			if err != nil {
				t.Fatalf("second merge: %v", err)
			}
			if second.Changed {
				t.Fatalf("second merge changed output:\nfirst  %q\nsecond %q", first.Output, second.Output)
			}
			for _, p := range second.Sections {
				if p.Differs {
					t.Fatalf("second merge reports differs: %+v", p)
				}
			}
		})
	}
}

func TestMergeRejectsBadIncoming(t *testing.T) {
	if _, err := Merge(nil, "loose = line\n[foo]\nk = v\n", KindConfig); err == nil {
		t.Fatalf("expected error for preamble text")
	}
	if _, err := Merge(nil, "", KindConfig); err == nil {
		t.Fatalf("expected error for empty incoming")
	}
}
