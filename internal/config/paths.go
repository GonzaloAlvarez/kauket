package config

import (
	"os"
	"path/filepath"
)

func Home() (string, error) {
	if v := os.Getenv("KAUKET_HOME"); v != "" {
		return filepath.Abs(v)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "kauket"), nil
}

func EnsureHome() (string, error) {
	home, err := Home()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(home, 0700); err != nil {
		return "", err
	}
	return home, nil
}

func ConfigPath(home string) string {
	return filepath.Join(home, "config.json")
}

func IdentitiesDir(home string) string {
	return filepath.Join(home, "identities")
}

func AdminIdentityPath(home string) string {
	return filepath.Join(home, "identities", "admin.txt")
}

func HostIdentityPath(home string) string {
	return filepath.Join(home, "identities", "host.txt")
}

func GitDir(home string) string {
	return filepath.Join(home, "git")
}

func DeployKeyPath(home string) string {
	return filepath.Join(home, "git", "deploy_key")
}

func DeployKeyPubPath(home string) string {
	return filepath.Join(home, "git", "deploy_key.pub")
}

func RepoDir(home string) string {
	return filepath.Join(home, "repo")
}

func StateDir(home string) string {
	return filepath.Join(home, "state")
}

func InstalledStatePath(home string) string {
	return filepath.Join(home, "state", "installed.json")
}

func LockPath(home string) string {
	return filepath.Join(home, "repo.lock")
}

func EnsureIdentitiesDir(home string) error {
	return os.MkdirAll(IdentitiesDir(home), 0700)
}

func EnsureGitDir(home string) error {
	return os.MkdirAll(GitDir(home), 0700)
}

func EnsureStateDir(home string) error {
	return os.MkdirAll(StateDir(home), 0700)
}

func EnvRepo() string {
	return os.Getenv("KAUKET_REPO")
}

func EnvRemote() string {
	return os.Getenv("KAUKET_REMOTE")
}

func EnvNoColor() bool {
	return os.Getenv("KAUKET_NO_COLOR") != ""
}

func EnvDebug() bool {
	return os.Getenv("KAUKET_DEBUG") != ""
}
