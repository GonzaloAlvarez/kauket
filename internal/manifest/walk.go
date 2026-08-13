package manifest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/bundle"
)

type WalkResult struct {
	Nodes    map[string]ManifestFile
	SpineIDs []string
	Index    *Index
}

func ObjectPath(objectsDir, id string) string {
	return filepath.Join(objectsDir, id+".age")
}

func ReadManifest(objectsDir, nodeID string, ip agebox.IdentityProvider) (ManifestFile, error) {
	ct, err := os.ReadFile(ObjectPath(objectsDir, nodeID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ManifestFile{}, fmt.Errorf("%w: manifest %s", ErrNotFound, nodeID)
		}
		return ManifestFile{}, fmt.Errorf("kauket: read manifest %s: %w", nodeID, err)
	}
	return DecodeManifest(ct, ip)
}

func checkPin(pins *Pins, body ManifestBody) error {
	if pins == nil {
		return nil
	}
	if pinned, ok := pins.NodeVersions[body.NodeID]; ok && body.Version < pinned {
		return fmt.Errorf("%w: node %s version %d < pinned %d", ErrRollback, body.NodeID, body.Version, pinned)
	}
	return nil
}

func advancePins(pins *Pins, nodes map[string]ManifestFile) {
	if pins == nil {
		return
	}
	for id, f := range nodes {
		if f.Body.Version > pins.NodeVersions[id] {
			pins.NodeVersions[id] = f.Body.Version
		}
	}
}

func verifyNode(f ManifestFile, root StoreRoot, parent *ManifestBody, pins *Pins, v bundle.Verifier) error {
	if f.Body.StoreID != root.StoreID {
		return fmt.Errorf("%w: manifest %s has store id %s", ErrStoreIDMismatch, f.Body.NodeID, f.Body.StoreID)
	}
	if parent == nil {
		anchors := make([]string, 0, len(root.TrustAnchors)+len(root.Recovery))
		for _, a := range root.TrustAnchors {
			anchors = append(anchors, a.SignPubkey)
		}
		for _, r := range root.Recovery {
			anchors = append(anchors, r.SignPubkey)
		}
		if err := VerifyManifest(f, anchors, v); err != nil {
			return err
		}
	} else {
		attested := make([]string, 0, len(parent.Children))
		for _, c := range parent.Children {
			if c.NodeID == f.Body.NodeID {
				if c.Name != "" && c.Name != f.Body.Name {
					return fmt.Errorf("%w: node %s name %q does not match parent attestation name %q", ErrUnattestedChild, f.Body.NodeID, f.Body.Name, c.Name)
				}
				attested = append(attested, c.OwnerSignKeys...)
				break
			}
		}
		for _, r := range root.Recovery {
			attested = append(attested, r.SignPubkey)
		}
		if len(attested) == 0 {
			return fmt.Errorf("%w: node %s not attested by parent %s", ErrUnattestedChild, f.Body.NodeID, parent.NodeID)
		}
		if err := VerifyManifest(f, attested, v); err != nil {
			if errors.Is(err, ErrUntrustedSigner) {
				return fmt.Errorf("%w: node %s signer not in parent attestation", ErrUnattestedChild, f.Body.NodeID)
			}
			return err
		}
	}
	return checkPin(pins, f.Body)
}

func WalkSpine(objectsDir string, root StoreRoot, pins *Pins, ip agebox.IdentityProvider, v bundle.Verifier, path []string) (*WalkResult, error) {
	res := &WalkResult{Nodes: map[string]ManifestFile{}}

	current, err := ReadManifest(objectsDir, root.RootNodeID, ip)
	if err != nil {
		return nil, err
	}
	if err := verifyNode(current, root, nil, pins, v); err != nil {
		return nil, err
	}
	res.Nodes[current.Body.NodeID] = current
	res.SpineIDs = append(res.SpineIDs, current.Body.NodeID)

	for _, segment := range path {
		parentBody := current.Body
		var next *ManifestFile
		for _, child := range parentBody.Children {
			if child.Name != "" && child.Name != segment {
				continue
			}
			childFile, err := ReadManifest(objectsDir, child.NodeID, ip)
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					return nil, err
				}
				continue
			}
			if childFile.Body.Name != segment {
				continue
			}
			if err := verifyNode(childFile, root, &parentBody, pins, v); err != nil {
				return nil, err
			}
			next = &childFile
			break
		}
		if next == nil {
			return nil, fmt.Errorf("%w: no readable child named %q under %s", ErrNotFound, segment, parentBody.Name)
		}
		current = *next
		res.Nodes[current.Body.NodeID] = current
		res.SpineIDs = append(res.SpineIDs, current.Body.NodeID)
	}

	advancePins(pins, res.Nodes)
	return res, nil
}

func LoadIndex(objectsDir string, body ManifestBody, ip agebox.IdentityProvider) (*Index, error) {
	ct, err := os.ReadFile(ObjectPath(objectsDir, body.IndexObjectID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: index %s", ErrNotFound, body.IndexObjectID)
		}
		return nil, fmt.Errorf("kauket: read index %s: %w", body.IndexObjectID, err)
	}
	ix, err := DecodeIndex(ct, ip, body.IndexSHA256)
	if err != nil {
		return nil, err
	}
	if ix.NodeID != body.NodeID {
		return nil, fmt.Errorf("%w: index node id %s does not match manifest %s", ErrHashMismatch, ix.NodeID, body.NodeID)
	}
	return &ix, nil
}

func LoadObject(objectsDir string, entry IndexEntry, ip agebox.IdentityProvider) (Object, error) {
	ct, err := os.ReadFile(ObjectPath(objectsDir, entry.ObjectID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Object{}, fmt.Errorf("%w: object %s", ErrNotFound, entry.ObjectID)
		}
		return Object{}, fmt.Errorf("kauket: read object %s: %w", entry.ObjectID, err)
	}
	return DecodeObject(ct, ip, entry.ObjectSHA256)
}

func LoadReadableTree(objectsDir string, root StoreRoot, pins *Pins, ip agebox.IdentityProvider, v bundle.Verifier) (map[string]ManifestFile, error) {
	nodes := map[string]ManifestFile{}
	rootFile, err := ReadManifest(objectsDir, root.RootNodeID, ip)
	if err != nil {
		return nil, err
	}
	if err := verifyNode(rootFile, root, nil, pins, v); err != nil {
		return nil, err
	}
	nodes[rootFile.Body.NodeID] = rootFile
	if err := loadChildren(objectsDir, root, rootFile.Body, pins, ip, v, nodes); err != nil {
		return nil, err
	}
	advancePins(pins, nodes)
	return nodes, nil
}

func loadChildren(objectsDir string, root StoreRoot, parent ManifestBody, pins *Pins, ip agebox.IdentityProvider, v bundle.Verifier, nodes map[string]ManifestFile) error {
	for _, child := range parent.Children {
		childFile, err := ReadManifest(objectsDir, child.NodeID, ip)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return err
			}
			continue
		}
		if err := verifyNode(childFile, root, &parent, pins, v); err != nil {
			return err
		}
		nodes[childFile.Body.NodeID] = childFile
		if err := loadChildren(objectsDir, root, childFile.Body, pins, ip, v, nodes); err != nil {
			return err
		}
	}
	return nil
}
