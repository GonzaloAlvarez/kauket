package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const stateSchema = 1

type State struct {
	Schema    int              `json:"schema"`
	Installed map[string]Entry `json:"installed"`
}

type Entry struct {
	Destination         string `json:"destination"`
	ExpandedDestination string `json:"expanded_destination"`
	SHA256              string `json:"sha256"`
	InstalledAt         string `json:"installed_at"`
}

func statePath(home string) string {
	return filepath.Join(home, "state", "installed.json")
}

func stateDir(home string) string {
	return filepath.Join(home, "state")
}

func LoadState(home string) (*State, error) {
	path := statePath(home)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &State{Schema: stateSchema, Installed: map[string]Entry{}}, nil
		}
		return nil, fmt.Errorf("install: read state: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("install: parse state: %w", err)
	}
	if s.Installed == nil {
		s.Installed = map[string]Entry{}
	}
	if s.Schema == 0 {
		s.Schema = stateSchema
	}
	return &s, nil
}

func SaveState(home string, s *State) error {
	if s == nil {
		return fmt.Errorf("install: nil state")
	}
	if s.Installed == nil {
		s.Installed = map[string]Entry{}
	}
	if s.Schema == 0 {
		s.Schema = stateSchema
	}
	dir := stateDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("install: create state dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("install: chmod state dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("install: marshal state: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".installed-")
	if err != nil {
		return fmt.Errorf("install: create state temp: %w", err)
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
		return fmt.Errorf("install: write state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("install: sync state: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("install: chmod state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("install: close state: %w", err)
	}
	if err := os.Rename(tmpPath, statePath(home)); err != nil {
		return fmt.Errorf("install: rename state: %w", err)
	}
	cleaned = true
	return nil
}
