package awsconfig

import "strings"

type FileKind int

const (
	KindConfig FileKind = iota
	KindCredentials
)

type Section struct {
	Header string
	Key    string
	Raw    string
}

type File struct {
	Preamble string
	Sections []Section
}

func Parse(data []byte, kind FileKind) File {
	lines := splitLines(string(data))
	var f File
	var current *Section
	var buf strings.Builder
	flush := func() {
		if current == nil {
			f.Preamble = buf.String()
		} else {
			current.Raw = buf.String()
			f.Sections = append(f.Sections, *current)
		}
		buf.Reset()
	}
	for _, line := range lines {
		if name, ok := headerName(line); ok {
			flush()
			current = &Section{Header: name, Key: SectionKey(name, kind)}
		}
		buf.WriteString(line)
	}
	flush()
	return f
}

func (f File) Render() []byte {
	var b strings.Builder
	b.WriteString(f.Preamble)
	for _, s := range f.Sections {
		b.WriteString(s.Raw)
	}
	return []byte(b.String())
}

func SectionKey(headerInner string, kind FileKind) string {
	name := strings.Join(strings.Fields(headerInner), " ")
	if kind == KindConfig {
		if rest, ok := strings.CutPrefix(name, "profile "); ok {
			return rest
		}
	}
	return name
}

func NormalizeSection(raw string) string {
	lines := splitLines(raw)
	end := len(lines)
	for end > 0 && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	out := strings.Join(lines[:end], "")
	if out == "" {
		return out
	}
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out
}

func splitLines(s string) []string {
	var lines []string
	for len(s) > 0 {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			lines = append(lines, s)
			break
		}
		lines = append(lines, s[:i+1])
		s = s[i+1:]
	}
	return lines
}

func headerName(line string) (string, bool) {
	if len(line) == 0 || line[0] != '[' {
		return "", false
	}
	end := strings.IndexByte(line, ']')
	if end < 0 {
		return "", false
	}
	return line[1:end], true
}
