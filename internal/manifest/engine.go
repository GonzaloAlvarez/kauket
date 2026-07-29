package manifest

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
	"github.com/gonzaloalvarez/kauket/internal/model"
)

type Op int

const (
	OpAdd Op = iota
	OpGrant
	OpRevoke
)

type Intent struct {
	Op       Op
	Path     []string
	Key      string
	Identity IdentityRecord
	Secret   *Object
	Force    bool
}

type Plan struct {
	Written  []string
	Rotation []string
	Residue  []string
	NoOp     bool
}

type Engine struct {
	ObjectsDir string
	Root       StoreRoot
	Pins       *Pins
	Identity   agebox.IdentityProvider
	Signer     bundle.Signer
	SignerPub  string
	ActorID    string
	Now        func() time.Time
}

func (e *Engine) recovery() []string {
	out := make([]string, 0, len(e.Root.Recovery))
	for _, r := range e.Root.Recovery {
		out = append(out, r.AgeRecipient)
	}
	return out
}

func (e *Engine) nowStr() string {
	now := e.Now
	if now == nil {
		now = time.Now
	}
	return now().UTC().Format(time.RFC3339)
}

func ownsNode(body ManifestBody, signPub string) bool {
	for _, o := range body.Owners {
		if o.SignPubkey == signPub {
			return true
		}
	}
	return false
}

type engineState struct {
	files map[string]ManifestFile
	tree  Tree
}

func (e *Engine) loadState() (*engineState, error) {
	files, err := LoadReadableTree(e.ObjectsDir, e.Root, e.Pins, e.Identity, bundle.Ed25519Verifier{})
	if err != nil {
		return nil, err
	}
	tree := Tree{}
	for id, f := range files {
		tree[id] = f.Body
	}
	return &engineState{files: files, tree: tree}, nil
}

func (s *engineState) resolvePath(rootID string, path []string) (existing []string, remaining []string, err error) {
	current := rootID
	existing = []string{rootID}
	for i, segment := range path {
		found := ""
		for _, child := range s.tree[current].Children {
			body, ok := s.tree[child.NodeID]
			if !ok {
				continue
			}
			if body.Name == segment {
				found = child.NodeID
				break
			}
		}
		if found == "" {
			return existing, path[i:], nil
		}
		current = found
		existing = append(existing, current)
	}
	return existing, nil, nil
}

func (e *Engine) Apply(in Intent) (*Plan, error) {
	state, err := e.loadState()
	if err != nil {
		return nil, err
	}
	switch in.Op {
	case OpAdd:
		return e.applyAdd(state, in)
	case OpGrant:
		return e.applyGrant(state, in)
	case OpRevoke:
		return e.applyRevoke(state, in)
	default:
		return nil, fmt.Errorf("kauket: unknown engine op %d", in.Op)
	}
}

func (e *Engine) applyAdd(state *engineState, in Intent) (*Plan, error) {
	if in.Secret == nil || in.Key == "" {
		return nil, fmt.Errorf("kauket: add intent requires a key and secret payload")
	}
	plan := &Plan{}
	spine, remaining, err := state.resolvePath(e.Root.RootNodeID, in.Path)
	if err != nil {
		return nil, err
	}
	attachID := spine[len(spine)-1]
	if !ownsNode(state.tree[attachID], e.SignerPub) {
		return nil, fmt.Errorf("%w: %s", ErrNotOwner, pathName(state.tree, attachID))
	}

	resigned := map[string]bool{}
	for _, segment := range remaining {
		parent := state.tree[attachID]
		child := ManifestBody{
			Schema: Schema, Kind: KindManifest, StoreID: e.Root.StoreID,
			NodeID: model.NewNodeID(), Version: 1, UpdatedAt: e.nowStr(),
			Name: segment, ParentID: attachID,
			Owners:        parent.Owners,
			Readers:       parent.Readers,
			IndexObjectID: model.NewIndexObjectID(),
		}
		ownerKeys := make([]string, 0, len(child.Owners))
		for _, o := range child.Owners {
			ownerKeys = append(ownerKeys, o.SignPubkey)
		}
		parent.Children = append(parent.Children, ChildAttestation{NodeID: child.NodeID, OwnerSignKeys: ownerKeys})
		parent.Version++
		parent.UpdatedAt = e.nowStr()
		state.tree[attachID] = parent
		resigned[attachID] = true

		state.tree[child.NodeID] = child
		state.files[child.NodeID] = ManifestFile{Body: child}
		emptyIx := Index{Schema: Schema, Kind: KindIndex, StoreID: e.Root.StoreID, NodeID: child.NodeID, Entries: map[string]IndexEntry{}}
		if err := e.writeIndex(state, child.NodeID, emptyIx, plan); err != nil {
			return nil, err
		}
		resigned[child.NodeID] = true
		attachID = child.NodeID
	}

	target := state.tree[attachID]
	ix, err := LoadIndex(e.ObjectsDir, target, e.Identity)
	if err != nil {
		return nil, err
	}
	prev, exists := ix.Entries[in.Key]
	if exists && !in.Force {
		return nil, fmt.Errorf("kauket: secret already exists at %s/%s; use --force to replace", pathName(state.tree, attachID), in.Key)
	}

	obj := *in.Secret
	obj.Schema = Schema
	obj.StoreID = e.Root.StoreID
	obj.ObjectID = model.NewObjectID()
	obj.UpdatedAt = e.nowStr()
	if exists {
		obj.CreatedAt = prev.CreatedAt
	} else {
		obj.CreatedAt = e.nowStr()
	}
	if obj.CreatedAt == "" {
		obj.CreatedAt = e.nowStr()
	}

	entry := IndexEntry{
		ObjectID:  obj.ObjectID,
		Kind:      obj.Kind,
		CreatedAt: obj.CreatedAt,
		UpdatedAt: obj.UpdatedAt,
	}
	if exists {
		entry.Readers = prev.Readers
	}
	ix.Entries[in.Key] = entry

	objRecipients, err := RecipientSet(ArtifactObject, attachID, in.Key, state.tree, ix, e.recovery())
	if err != nil {
		return nil, err
	}
	objCT, objSHA, err := EncodeObject(obj, agebox.X25519RecipientProvider{Strings: objRecipients})
	if err != nil {
		return nil, err
	}
	if err := e.writeFile(obj.ObjectID, objCT, plan); err != nil {
		return nil, err
	}
	entry.ObjectSHA256 = objSHA
	ix.Entries[in.Key] = entry
	if exists && prev.ObjectID != obj.ObjectID {
		e.removeFile(prev.ObjectID)
	}

	if err := e.writeIndex(state, attachID, *ix, plan); err != nil {
		return nil, err
	}
	resigned[attachID] = true

	if err := e.resignAndWrite(state, resigned, plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func (e *Engine) applyGrant(state *engineState, in Intent) (*Plan, error) {
	plan := &Plan{}
	nodeID, ix, err := e.targetNode(state, in.Path)
	if err != nil {
		return nil, err
	}
	body := state.tree[nodeID]
	if !ownsNode(body, e.SignerPub) {
		return nil, fmt.Errorf("%w: %s", ErrNotOwner, pathName(state.tree, nodeID))
	}
	member := Member{IID: in.Identity.ID, AgeRecipient: in.Identity.AgeRecipient}
	if member.AgeRecipient == "" {
		return nil, fmt.Errorf("kauket: identity %s has no age recipient", in.Identity.ID)
	}

	if in.Key != "" {
		entry, ok := ix.Entries[in.Key]
		if !ok {
			return nil, fmt.Errorf("%w: entry %q", ErrNotFound, in.Key)
		}
		if hasMember(entry.Readers, member.IID) {
			plan.NoOp = true
			return plan, nil
		}
		entry.Readers = append(entry.Readers, member)
		entry.UpdatedAt = e.nowStr()
		ix.Entries[in.Key] = entry
		if !hasMember(body.ExtraReaders, member.IID) {
			body.ExtraReaders = append(body.ExtraReaders, member)
		}
	} else {
		if hasMember(body.Readers, member.IID) || ownerHas(body.Owners, member.IID) {
			plan.NoOp = true
			return plan, nil
		}
		body.Readers = append(body.Readers, member)
	}
	body.Version++
	body.UpdatedAt = e.nowStr()
	state.tree[nodeID] = body

	if err := e.reencodeNodeContent(state, nodeID, ix, plan, in.Key); err != nil {
		return nil, err
	}
	if err := e.resignAndWrite(state, map[string]bool{nodeID: true}, plan); err != nil {
		return nil, err
	}
	if err := e.widenAncestors(state, nodeID, member.AgeRecipient, plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func (e *Engine) applyRevoke(state *engineState, in Intent) (*Plan, error) {
	plan := &Plan{}
	nodeID, ix, err := e.targetNode(state, in.Path)
	if err != nil {
		return nil, err
	}
	body := state.tree[nodeID]
	if !ownsNode(body, e.SignerPub) {
		return nil, fmt.Errorf("%w: %s", ErrNotOwner, pathName(state.tree, nodeID))
	}

	removed := false
	if in.Key != "" {
		entry, ok := ix.Entries[in.Key]
		if !ok {
			return nil, fmt.Errorf("%w: entry %q", ErrNotFound, in.Key)
		}
		if hasMember(entry.Readers, in.Identity.ID) {
			entry.Readers = removeMember(entry.Readers, in.Identity.ID)
			entry.UpdatedAt = e.nowStr()
			ix.Entries[in.Key] = entry
			removed = true
			plan.Rotation = append(plan.Rotation, pathName(state.tree, nodeID)+"/"+in.Key)
		}
		stillEntry := false
		for name, other := range ix.Entries {
			if name != in.Key && hasMember(other.Readers, in.Identity.ID) {
				stillEntry = true
				break
			}
		}
		if !stillEntry {
			body.ExtraReaders = removeMember(body.ExtraReaders, in.Identity.ID)
		}
	} else {
		if hasMember(body.Readers, in.Identity.ID) {
			body.Readers = removeMember(body.Readers, in.Identity.ID)
			removed = true
			for name := range ix.Entries {
				plan.Rotation = append(plan.Rotation, pathName(state.tree, nodeID)+"/"+name)
			}
		}
	}
	if !removed {
		plan.NoOp = true
		return plan, nil
	}
	sort.Strings(plan.Rotation)
	body.Version++
	body.UpdatedAt = e.nowStr()
	state.tree[nodeID] = body

	if err := e.reencodeNodeContent(state, nodeID, ix, plan, ""); err != nil {
		return nil, err
	}
	if err := e.resignAndWrite(state, map[string]bool{nodeID: true}, plan); err != nil {
		return nil, err
	}
	if err := e.shrinkAncestors(state, nodeID, plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func (e *Engine) targetNode(state *engineState, path []string) (string, *Index, error) {
	spine, remaining, err := state.resolvePath(e.Root.RootNodeID, path)
	if err != nil {
		return "", nil, err
	}
	if len(remaining) > 0 {
		return "", nil, fmt.Errorf("%w: namespace %v", ErrNotFound, path)
	}
	nodeID := spine[len(spine)-1]
	ix, err := LoadIndex(e.ObjectsDir, state.tree[nodeID], e.Identity)
	if err != nil {
		return "", nil, err
	}
	return nodeID, ix, nil
}

func (e *Engine) reencodeNodeContent(state *engineState, nodeID string, ix *Index, plan *Plan, onlyEntry string) error {
	body := state.tree[nodeID]
	names := make([]string, 0, len(ix.Entries))
	for name := range ix.Entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if onlyEntry != "" && name != onlyEntry {
			continue
		}
		entry := ix.Entries[name]
		obj, err := LoadObject(e.ObjectsDir, entry, e.Identity)
		if err != nil {
			return err
		}
		recipients, err := RecipientSet(ArtifactObject, nodeID, name, state.tree, ix, e.recovery())
		if err != nil {
			return err
		}
		ct, sha, err := EncodeObject(obj, agebox.X25519RecipientProvider{Strings: recipients})
		if err != nil {
			return err
		}
		entry.ObjectSHA256 = sha
		ix.Entries[name] = entry
		if err := e.writeFile(entry.ObjectID, ct, plan); err != nil {
			return err
		}
	}
	if err := e.writeIndex(state, nodeID, *ix, plan); err != nil {
		return err
	}
	_ = body
	return nil
}

func (e *Engine) writeIndex(state *engineState, nodeID string, ix Index, plan *Plan) error {
	recipients, err := RecipientSet(ArtifactIndex, nodeID, "", state.tree, nil, e.recovery())
	if err != nil {
		return err
	}
	ct, sha, err := EncodeIndex(ix, agebox.X25519RecipientProvider{Strings: recipients})
	if err != nil {
		return err
	}
	body := state.tree[nodeID]
	if err := e.writeFile(body.IndexObjectID, ct, plan); err != nil {
		return err
	}
	body.IndexSHA256 = sha
	state.tree[nodeID] = body
	return nil
}

func (e *Engine) resignAndWrite(state *engineState, nodeIDs map[string]bool, plan *Plan) error {
	ids := make([]string, 0, len(nodeIDs))
	for id := range nodeIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		body := state.tree[id]
		signed, err := SignBody(body, e.Signer)
		if err != nil {
			return err
		}
		recipients, err := RecipientSet(ArtifactManifest, id, "", state.tree, nil, e.recovery())
		if err != nil {
			return err
		}
		ct, _, err := EncodeManifest(ManifestFile{Body: signed, Recipients: recipients}, agebox.X25519RecipientProvider{Strings: recipients})
		if err != nil {
			return err
		}
		if err := e.writeFile(id, ct, plan); err != nil {
			return err
		}
		state.tree[id] = signed
		if e.Pins != nil && signed.Version > e.Pins.NodeVersions[id] {
			e.Pins.NodeVersions[id] = signed.Version
		}
	}
	return nil
}

func (e *Engine) widenAncestors(state *engineState, nodeID, newRecipient string, plan *Plan) error {
	current := state.tree[nodeID].ParentID
	for current != "" {
		file, ok := state.files[current]
		if !ok {
			return fmt.Errorf("%w: ancestor %s", ErrNotFound, current)
		}
		has := false
		for _, r := range file.Recipients {
			if r == newRecipient {
				has = true
				break
			}
		}
		if !has {
			file.Recipients = append(file.Recipients, newRecipient)
			sort.Strings(file.Recipients)
			ct, _, err := EncodeManifest(file, agebox.X25519RecipientProvider{Strings: file.Recipients})
			if err != nil {
				return err
			}
			if err := e.writeFile(current, ct, plan); err != nil {
				return err
			}
			state.files[current] = file
		}
		current = file.Body.ParentID
	}
	return nil
}

func (e *Engine) shrinkAncestors(state *engineState, nodeID string, plan *Plan) error {
	current := state.tree[nodeID].ParentID
	for current != "" {
		file := state.files[current]
		if ownsNode(file.Body, e.SignerPub) {
			recipients, err := RecipientSet(ArtifactManifest, current, "", state.tree, nil, e.recovery())
			if err != nil {
				return err
			}
			file.Recipients = recipients
			ct, _, err := EncodeManifest(file, agebox.X25519RecipientProvider{Strings: recipients})
			if err != nil {
				return err
			}
			if err := e.writeFile(current, ct, plan); err != nil {
				return err
			}
			state.files[current] = file
		} else {
			plan.Residue = append(plan.Residue, current)
		}
		current = file.Body.ParentID
	}
	return nil
}

func (e *Engine) writeFile(id string, ct []byte, plan *Plan) error {
	path := ObjectPath(e.ObjectsDir, id)
	if err := os.MkdirAll(e.ObjectsDir, 0o700); err != nil {
		return fmt.Errorf("kauket: ensure objects dir: %w", err)
	}
	if err := os.WriteFile(path, ct, 0o600); err != nil {
		return fmt.Errorf("kauket: write object %s: %w", id, err)
	}
	plan.Written = append(plan.Written, id)
	return nil
}

func (e *Engine) removeFile(id string) {
	_ = os.Remove(ObjectPath(e.ObjectsDir, id))
}

func hasMember(members []Member, iid string) bool {
	for _, m := range members {
		if m.IID == iid {
			return true
		}
	}
	return false
}

func ownerHas(owners []Owner, iid string) bool {
	for _, o := range owners {
		if o.IID == iid {
			return true
		}
	}
	return false
}

func removeMember(members []Member, iid string) []Member {
	out := members[:0]
	for _, m := range members {
		if m.IID != iid {
			out = append(out, m)
		}
	}
	return out
}

func pathName(tree Tree, nodeID string) string {
	body := tree[nodeID]
	if body.ParentID == "" {
		return "/"
	}
	parent := pathName(tree, body.ParentID)
	if parent == "/" {
		return body.Name
	}
	return parent + "/" + body.Name
}
