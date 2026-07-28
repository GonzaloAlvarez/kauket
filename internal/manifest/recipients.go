package manifest

import (
	"fmt"
	"sort"
)

type ArtifactKind int

const (
	ArtifactManifest ArtifactKind = iota
	ArtifactIndex
	ArtifactObject
)

type Tree map[string]ManifestBody

func RecipientSet(kind ArtifactKind, nodeID, entryName string, tree Tree, ix *Index, recovery []string) ([]string, error) {
	node, ok := tree[nodeID]
	if !ok {
		return nil, fmt.Errorf("%w: node %s not in tree", ErrNotFound, nodeID)
	}
	set := map[string]struct{}{}
	addMembers(set, node)

	switch kind {
	case ArtifactManifest:
		if err := addDescendants(set, node, tree); err != nil {
			return nil, err
		}
		if err := addAncestorOwners(set, node, tree); err != nil {
			return nil, err
		}
	case ArtifactIndex:
	case ArtifactObject:
		if ix == nil {
			return nil, fmt.Errorf("%w: index required for object recipient set", ErrNotFound)
		}
		entry, ok := ix.Entries[entryName]
		if !ok {
			return nil, fmt.Errorf("%w: entry %q not in index of node %s", ErrNotFound, entryName, nodeID)
		}
		for _, r := range entry.Readers {
			set[r.AgeRecipient] = struct{}{}
		}
	default:
		return nil, fmt.Errorf("kauket: unknown artifact kind %d", kind)
	}

	for _, r := range recovery {
		set[r] = struct{}{}
	}

	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out, nil
}

func addMembers(set map[string]struct{}, body ManifestBody) {
	for _, o := range body.Owners {
		set[o.AgeRecipient] = struct{}{}
	}
	for _, r := range body.Readers {
		set[r.AgeRecipient] = struct{}{}
	}
	for _, r := range body.ExtraReaders {
		set[r.AgeRecipient] = struct{}{}
	}
}

func addDescendants(set map[string]struct{}, body ManifestBody, tree Tree) error {
	for _, child := range body.Children {
		childBody, ok := tree[child.NodeID]
		if !ok {
			return fmt.Errorf("%w: child %s of %s not in tree", ErrNotFound, child.NodeID, body.NodeID)
		}
		addMembers(set, childBody)
		if err := addDescendants(set, childBody, tree); err != nil {
			return err
		}
	}
	return nil
}

func addAncestorOwners(set map[string]struct{}, body ManifestBody, tree Tree) error {
	current := body
	for current.ParentID != "" {
		parent, ok := tree[current.ParentID]
		if !ok {
			return fmt.Errorf("%w: parent %s of %s not in tree", ErrNotFound, current.ParentID, current.NodeID)
		}
		for _, o := range parent.Owners {
			set[o.AgeRecipient] = struct{}{}
		}
		current = parent
	}
	return nil
}
