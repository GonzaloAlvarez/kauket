package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const ConfigSchema = 1

type Role string

const (
	RoleAdmin         Role = "admin"
	RoleClient        Role = "client"
	RoleUninitialized Role = ""
)

type RepoInfo struct {
	Owner         string `json:"owner"`
	Name          string `json:"name"`
	RemoteHTTPS   string `json:"remote_https"`
	RemoteSSH     string `json:"remote_ssh"`
	DefaultBranch string `json:"default_branch"`
}

type CommitAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type AdminInfo struct {
	RecipientID  string `json:"recipient_id"`
	IdentityPath string `json:"identity_path"`
}

type HostInfo struct {
	ID            string `json:"id"`
	DisplayName   string `json:"display_name"`
	IdentityPath  string `json:"identity_path"`
	DeployKeyPath string `json:"deploy_key_path"`
}

type Admin struct {
	Schema       int          `json:"schema"`
	Role         Role         `json:"role"`
	StoreID      string       `json:"store_id"`
	Repo         RepoInfo     `json:"repo"`
	Admin        AdminInfo    `json:"admin"`
	CommitAuthor CommitAuthor `json:"commit_author"`
}

type Client struct {
	Schema       int          `json:"schema"`
	Role         Role         `json:"role"`
	StoreID      string       `json:"store_id"`
	Host         HostInfo     `json:"host"`
	Repo         RepoInfo     `json:"repo"`
	CommitAuthor CommitAuthor `json:"commit_author"`
}

var (
	ErrNotAdmin  = errors.New("kauket: config role is not admin")
	ErrNotClient = errors.New("kauket: config role is not client")
	ErrNoConfig  = errors.New("kauket: no kauket config found")
)

type rolePeek struct {
	Role Role `json:"role"`
}

func DefaultRepoInfo(owner, name string) RepoInfo {
	return RepoInfo{
		Owner:         owner,
		Name:          name,
		RemoteHTTPS:   fmt.Sprintf("https://github.com/%s/%s.git", owner, name),
		RemoteSSH:     fmt.Sprintf("git@github.com:%s/%s.git", owner, name),
		DefaultBranch: "main",
	}
}

func PeekRole(home string) (Role, error) {
	data, err := os.ReadFile(ConfigPath(home))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return RoleUninitialized, nil
		}
		return RoleUninitialized, err
	}
	var p rolePeek
	if err := json.Unmarshal(data, &p); err != nil {
		return RoleUninitialized, fmt.Errorf("kauket: malformed config.json: %w", err)
	}
	return p.Role, nil
}

func LoadAdmin(home string) (*Admin, error) {
	data, err := os.ReadFile(ConfigPath(home))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoConfig
		}
		return nil, err
	}
	var p rolePeek
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("kauket: malformed config.json: %w", err)
	}
	if p.Role != RoleAdmin {
		return nil, ErrNotAdmin
	}
	var cfg Admin
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("kauket: malformed admin config.json: %w", err)
	}
	return &cfg, nil
}

func LoadClient(home string) (*Client, error) {
	data, err := os.ReadFile(ConfigPath(home))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoConfig
		}
		return nil, err
	}
	var p rolePeek
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("kauket: malformed config.json: %w", err)
	}
	if p.Role != RoleClient {
		return nil, ErrNotClient
	}
	var cfg Client
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("kauket: malformed client config.json: %w", err)
	}
	return &cfg, nil
}

func SaveAdmin(home string, cfg *Admin) error {
	if err := os.MkdirAll(filepath.Dir(ConfigPath(home)), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigPath(home), data, 0600)
}

func SaveClient(home string, cfg *Client) error {
	if err := os.MkdirAll(filepath.Dir(ConfigPath(home)), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigPath(home), data, 0600)
}
