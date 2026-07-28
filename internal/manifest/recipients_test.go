package manifest

import (
	"errors"
	"reflect"
	"sort"
	"testing"
)

func member(id, recipient string) Member {
	return Member{IID: id, AgeRecipient: recipient}
}

func owner(id, recipient, key string) Owner {
	return Owner{IID: id, AgeRecipient: recipient, SignPubkey: key}
}

func testTree() Tree {
	return Tree{
		"n_root": {
			NodeID:   "n_root",
			ParentID: "",
			Children: []ChildAttestation{{NodeID: "n_mid"}, {NodeID: "n_side"}},
			Owners:   []Owner{owner("i_rootowner", "age1rootowner", "k1")},
		},
		"n_mid": {
			NodeID:   "n_mid",
			ParentID: "n_root",
			Children: []ChildAttestation{{NodeID: "n_leaf"}},
			Owners:   []Owner{owner("i_midowner", "age1midowner", "k2")},
			Readers:  []Member{member("h_midreader", "age1midreader")},
		},
		"n_leaf": {
			NodeID:       "n_leaf",
			ParentID:     "n_mid",
			Owners:       []Owner{owner("i_leafowner", "age1leafowner", "k3")},
			Readers:      []Member{member("h_leafreader", "age1leafreader")},
			ExtraReaders: []Member{member("i_extrareader", "age1extrareader")},
		},
		"n_side": {
			NodeID:   "n_side",
			ParentID: "n_root",
			Readers:  []Member{member("h_sidereader", "age1sidereader")},
		},
	}
}

func testIndexWithEntry() *Index {
	return &Index{
		Schema:  Schema,
		Kind:    KindIndex,
		StoreID: "ks_x",
		NodeID:  "n_leaf",
		Entries: map[string]IndexEntry{
			"key1": {ObjectID: "o_1", Readers: []Member{member("i_entryonly", "age1entryonly")}},
			"key2": {ObjectID: "o_2"},
		},
	}
}

func TestRecipientSetTable(t *testing.T) {
	recovery := []string{"age1recovery"}
	cases := []struct {
		name      string
		kind      ArtifactKind
		nodeID    string
		entryName string
		ix        *Index
		recovery  []string
		want      []string
		wantErr   error
	}{
		{
			name: "manifest leaf includes members ancestors recovery",
			kind: ArtifactManifest, nodeID: "n_leaf", recovery: recovery,
			want: []string{"age1extrareader", "age1leafowner", "age1leafreader", "age1midowner", "age1recovery", "age1rootowner"},
		},
		{
			name: "manifest mid includes descendants",
			kind: ArtifactManifest, nodeID: "n_mid", recovery: recovery,
			want: []string{"age1extrareader", "age1leafowner", "age1leafreader", "age1midowner", "age1midreader", "age1recovery", "age1rootowner"},
		},
		{
			name: "manifest root includes every member in store",
			kind: ArtifactManifest, nodeID: "n_root", recovery: recovery,
			want: []string{"age1extrareader", "age1leafowner", "age1leafreader", "age1midowner", "age1midreader", "age1recovery", "age1rootowner", "age1sidereader"},
		},
		{
			name: "manifest sibling subtree not in leaf set",
			kind: ArtifactManifest, nodeID: "n_leaf", recovery: nil,
			want: []string{"age1extrareader", "age1leafowner", "age1leafreader", "age1midowner", "age1rootowner"},
		},
		{
			name: "index is members plus recovery only",
			kind: ArtifactIndex, nodeID: "n_leaf", recovery: recovery,
			want: []string{"age1extrareader", "age1leafowner", "age1leafreader", "age1recovery"},
		},
		{
			name: "index excludes ancestors and descendants",
			kind: ArtifactIndex, nodeID: "n_mid", recovery: nil,
			want: []string{"age1midowner", "age1midreader"},
		},
		{
			name: "object adds entry readers",
			kind: ArtifactObject, nodeID: "n_leaf", entryName: "key1", ix: testIndexWithEntry(), recovery: recovery,
			want: []string{"age1entryonly", "age1extrareader", "age1leafowner", "age1leafreader", "age1recovery"},
		},
		{
			name: "object without entry readers equals index set",
			kind: ArtifactObject, nodeID: "n_leaf", entryName: "key2", ix: testIndexWithEntry(), recovery: recovery,
			want: []string{"age1extrareader", "age1leafowner", "age1leafreader", "age1recovery"},
		},
		{
			name: "no recovery when opted out",
			kind: ArtifactIndex, nodeID: "n_leaf", recovery: nil,
			want: []string{"age1extrareader", "age1leafowner", "age1leafreader"},
		},
		{
			name: "reader only node still has ancestor owners in manifest",
			kind: ArtifactManifest, nodeID: "n_side", recovery: nil,
			want: []string{"age1rootowner", "age1sidereader"},
		},
		{
			name: "unknown node errors",
			kind: ArtifactManifest, nodeID: "n_missing", wantErr: ErrNotFound,
		},
		{
			name: "object without index errors",
			kind: ArtifactObject, nodeID: "n_leaf", entryName: "key1", ix: nil, wantErr: ErrNotFound,
		},
		{
			name: "object with missing entry errors",
			kind: ArtifactObject, nodeID: "n_leaf", entryName: "absent", ix: testIndexWithEntry(), wantErr: ErrNotFound,
		},
		{
			name: "duplicate recipients dedupe",
			kind: ArtifactIndex, nodeID: "n_dup", recovery: []string{"age1dup"},
			want: []string{"age1dup"},
		},
	}
	tree := testTree()
	tree["n_dup"] = ManifestBody{
		NodeID:  "n_dup",
		Owners:  []Owner{owner("i_a", "age1dup", "k")},
		Readers: []Member{member("h_b", "age1dup")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RecipientSet(tc.kind, tc.nodeID, tc.entryName, tree, tc.ix, tc.recovery)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("RecipientSet: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("set = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRecipientSetMissingChildErrors(t *testing.T) {
	tree := testTree()
	body := tree["n_root"]
	body.Children = append(body.Children, ChildAttestation{NodeID: "n_ghost"})
	tree["n_root"] = body
	if _, err := RecipientSet(ArtifactManifest, "n_root", "", tree, nil, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound for missing child", err)
	}
}

func TestRecipientSetMissingParentErrors(t *testing.T) {
	tree := testTree()
	delete(tree, "n_root")
	if _, err := RecipientSet(ArtifactManifest, "n_leaf", "", tree, nil, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound for missing parent", err)
	}
}

func TestRecipientSetProperties(t *testing.T) {
	tree := testTree()
	recovery := []string{"age1recovery"}
	for _, nodeID := range []string{"n_root", "n_mid", "n_leaf", "n_side"} {
		manifestSet, err := RecipientSet(ArtifactManifest, nodeID, "", tree, nil, recovery)
		if err != nil {
			t.Fatalf("manifest set %s: %v", nodeID, err)
		}
		indexSet, err := RecipientSet(ArtifactIndex, nodeID, "", tree, nil, recovery)
		if err != nil {
			t.Fatalf("index set %s: %v", nodeID, err)
		}
		if !sort.StringsAreSorted(manifestSet) || !sort.StringsAreSorted(indexSet) {
			t.Fatalf("%s: sets not sorted", nodeID)
		}
		manifestHas := map[string]bool{}
		for _, r := range manifestSet {
			manifestHas[r] = true
		}
		for _, r := range indexSet {
			if !manifestHas[r] {
				t.Fatalf("%s: index recipient %s not in manifest set", nodeID, r)
			}
		}
		for _, o := range tree[nodeID].Owners {
			if !manifestHas[o.AgeRecipient] {
				t.Fatalf("%s: owner %s missing from manifest set", nodeID, o.AgeRecipient)
			}
		}
		if !manifestHas["age1recovery"] {
			t.Fatalf("%s: recovery missing", nodeID)
		}
		seen := map[string]bool{}
		for _, r := range manifestSet {
			if seen[r] {
				t.Fatalf("%s: duplicate %s", nodeID, r)
			}
			seen[r] = true
		}
	}
}

func TestRecipientSetDeterministic(t *testing.T) {
	tree := testTree()
	first, err := RecipientSet(ArtifactManifest, "n_root", "", tree, nil, []string{"age1recovery"})
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	for i := 0; i < 50; i++ {
		again, err := RecipientSet(ArtifactManifest, "n_root", "", tree, nil, []string{"age1recovery"})
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("iteration %d: nondeterministic output", i)
		}
	}
}
