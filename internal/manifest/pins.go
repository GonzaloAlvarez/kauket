package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const pinsSchema = 1

type Pins struct {
	Schema              int            `json:"schema"`
	StoreID             string         `json:"store_id"`
	StoreVersion        int            `json:"store_version,omitempty"`
	TrustAnchors        []TrustAnchor  `json:"trust_anchors"`
	RecoverySignPubkeys []string       `json:"recovery_sign_pubkeys"`
	NodeVersions        map[string]int `json:"node_versions"`
	UpdatedAt           string         `json:"updated_at"`
}

func (p *Pins) PinnedSignKeys() []string {
	keys := make([]string, 0, len(p.TrustAnchors)+len(p.RecoverySignPubkeys))
	for _, a := range p.TrustAnchors {
		keys = append(keys, a.SignPubkey)
	}
	keys = append(keys, p.RecoverySignPubkeys...)
	return keys
}

func LoadPins(path string) (*Pins, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Pins{Schema: pinsSchema, NodeVersions: map[string]int{}}, nil
		}
		return nil, fmt.Errorf("kauket: read pins: %w", err)
	}
	var p Pins
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("kauket: parse pins: %w", err)
	}
	if p.NodeVersions == nil {
		p.NodeVersions = map[string]int{}
	}
	if p.Schema == 0 {
		p.Schema = pinsSchema
	}
	return &p, nil
}

func SavePins(path string, p *Pins) error {
	if p == nil {
		return fmt.Errorf("kauket: nil pins")
	}
	if p.Schema == 0 {
		p.Schema = pinsSchema
	}
	if p.NodeVersions == nil {
		p.NodeVersions = map[string]int{}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("kauket: create pins dir: %w", err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("kauket: marshal pins: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".pins-")
	if err != nil {
		return fmt.Errorf("kauket: create pins temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleaned := false
	defer func() {
		if !cleaned {
			os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("kauket: write pins: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("kauket: sync pins: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("kauket: chmod pins: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("kauket: close pins: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("kauket: rename pins: %w", err)
	}
	cleaned = true
	return nil
}
