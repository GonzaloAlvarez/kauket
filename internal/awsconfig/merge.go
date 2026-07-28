package awsconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

type SectionPlan struct {
	Header         string
	Key            string
	Existing       bool
	Differs        bool
	ExistingSHA256 string
	IncomingSHA256 string
	Duplicates     int
}

type MergeResult struct {
	Output   []byte
	Changed  bool
	Sections []SectionPlan
}

type mergeChunk struct {
	text     string
	written  bool
	appended bool
}

func Merge(existing []byte, incoming string, kind FileKind) (MergeResult, error) {
	inc := Parse([]byte(incoming), kind)
	if strings.TrimSpace(inc.Preamble) != "" {
		return MergeResult{}, errors.New("aws profile content has text before the first section header")
	}
	if len(inc.Sections) == 0 {
		return MergeResult{}, errors.New("aws profile content has no sections")
	}

	plans := make([]SectionPlan, len(inc.Sections))
	norms := make([]string, len(inc.Sections))
	planIdx := make(map[string]int, len(inc.Sections))
	for i, s := range inc.Sections {
		norms[i] = NormalizeSection(s.Raw)
		plans[i] = SectionPlan{Header: s.Header, Key: s.Key, IncomingSHA256: shaHex(norms[i])}
		planIdx[s.Key] = i
	}

	target := Parse(existing, kind)
	var chunks []mergeChunk
	if target.Preamble != "" {
		chunks = append(chunks, mergeChunk{text: target.Preamble})
	}
	for _, ts := range target.Sections {
		i, isIncoming := planIdx[ts.Key]
		if !isIncoming {
			chunks = append(chunks, mergeChunk{text: ts.Raw})
			continue
		}
		if plans[i].Existing {
			plans[i].Duplicates++
			continue
		}
		exNorm := NormalizeSection(ts.Raw)
		plans[i].Existing = true
		plans[i].Differs = exNorm != norms[i]
		plans[i].ExistingSHA256 = shaHex(exNorm)
		chunks = append(chunks, mergeChunk{text: norms[i], written: true})
	}
	for i := range inc.Sections {
		if plans[i].Existing {
			continue
		}
		chunks = append(chunks, mergeChunk{text: norms[i], written: true, appended: true})
	}

	for i := range chunks {
		if !chunks[i].written {
			continue
		}
		if i < len(chunks)-1 {
			chunks[i].text += "\n"
		}
		if chunks[i].appended && i > 0 && !chunks[i-1].written {
			prev := chunks[i-1].text
			if !strings.HasSuffix(prev, "\n") {
				prev += "\n"
			}
			if !strings.HasSuffix(prev, "\n\n") {
				prev += "\n"
			}
			chunks[i-1].text = prev
		}
	}

	var b strings.Builder
	for _, c := range chunks {
		b.WriteString(c.text)
	}
	out := []byte(b.String())
	return MergeResult{
		Output:   out,
		Changed:  !bytes.Equal(out, existing),
		Sections: plans,
	}, nil
}

func shaHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
