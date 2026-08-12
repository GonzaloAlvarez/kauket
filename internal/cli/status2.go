package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gonzaloalvarez/kauket/internal/app"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/config"
	"github.com/gonzaloalvarez/kauket/internal/manifest"
)

func readableEntryPaths(vctx *v2Context) ([]string, int, error) {
	dir := objectsDir(vctx.repoDir)
	nodes, err := manifest.LoadReadableTree(dir, vctx.root, vctx.pins, vctx.identity, bundle.Ed25519Verifier{})
	if err != nil {
		return nil, 0, err
	}
	pathOf := map[string]string{}
	var buildPath func(id string) string
	buildPath = func(id string) string {
		if p, ok := pathOf[id]; ok {
			return p
		}
		body := nodes[id].Body
		if body.ParentID == "" {
			pathOf[id] = ""
			return ""
		}
		parentPath := buildPath(body.ParentID)
		p := body.Name
		if parentPath != "" {
			p = parentPath + "." + body.Name
		}
		pathOf[id] = p
		return p
	}
	var out []string
	for id := range nodes {
		body := nodes[id].Body
		if body.IndexObjectID == "" {
			continue
		}
		ix, err := manifest.LoadIndex(dir, body, vctx.identity)
		if err != nil {
			if isNoIdentityMatch(err) {
				continue
			}
			return nil, 0, err
		}
		prefix := buildPath(id)
		for name := range ix.Entries {
			full := name
			if prefix != "" {
				full = prefix + "." + name
			}
			out = append(out, full)
		}
	}
	sort.Strings(out)
	return out, len(nodes), nil
}

func statusV2(a *app.App, home string, role config.Role, identityPath string, v2 *config.V2Local) error {
	vctx, err := loadV2Context(home, identityPath, v2)
	if err != nil {
		return translateV2ReadError(err)
	}
	entries, nodeCount, err := readableEntryPaths(vctx)
	if err != nil {
		if !isNoIdentityMatch(err) {
			return translateV2ReadError(err)
		}
		entries, nodeCount = nil, 0
	}
	if err := vctx.savePins(); err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	a.UI.Println(fmt.Sprintf("role: %s", role))
	a.UI.Println(fmt.Sprintf("store: %s/%s", vctx.root.GitHub.Owner, vctx.root.GitHub.Repo))
	a.UI.Println("schema: 2")
	a.UI.Println(fmt.Sprintf("nodes readable: %d", nodeCount))
	a.UI.Println(fmt.Sprintf("entries readable: %d", len(entries)))
	return nil
}

func listV2(a *app.App, home string, identityPath string, v2 *config.V2Local) error {
	vctx, err := loadV2Context(home, identityPath, v2)
	if err != nil {
		return translateV2ReadError(err)
	}
	entries, _, err := readableEntryPaths(vctx)
	if err != nil {
		return translateV2ReadError(err)
	}
	if err := vctx.savePins(); err != nil {
		return &ExitError{Code: ExitUsage, Err: err}
	}
	for _, e := range entries {
		a.UI.Println(strings.TrimSpace(e))
	}
	return nil
}
