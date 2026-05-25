//go:build e2e || github_e2e

package e2e_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	cryptossh "golang.org/x/crypto/ssh"
)

type runResult struct {
	stdout string
	stderr string
	err    error
}

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "kauket")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/kauket")
	cmd.Dir = root
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, string(out))
	}
	return bin
}

func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("could not find go.mod above " + wd)
		}
		dir = parent
	}
}

func setupBareRemote(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir bare: %v", err)
	}
	repo, err := gogit.PlainInit(dir, true)
	if err != nil {
		t.Fatalf("bare init: %v", err)
	}
	headRef := plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.NewBranchReferenceName("main"))
	if err := repo.Storer.SetReference(headRef); err != nil {
		t.Fatalf("set HEAD: %v", err)
	}
	return "file://" + dir
}

func runKauket(t *testing.T, bin, kauketHome, home string, args ...string) runResult {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(),
		"KAUKET_HOME="+kauketHome,
		"HOME="+home,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return runResult{stdout: stdout.String(), stderr: stderr.String(), err: err}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	got := info.Mode().Perm()
	if got != want {
		t.Fatalf("mode for %s: want %v, got %v", path, want, got)
	}
}

func mustResolvedTempRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	return resolved
}

func mustMkdir(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(dir, mode); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func readHostID(t *testing.T, clientKauket string) string {
	t.Helper()
	cfgPath := filepath.Join(clientKauket, "config.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read client config: %v", err)
	}
	s := string(data)
	idx := strings.Index(s, `"host"`)
	if idx < 0 {
		t.Fatalf("client config missing host block: %s", s)
	}
	rest := s[idx:]
	idIdx := strings.Index(rest, `"id"`)
	if idIdx < 0 {
		t.Fatalf("client config host missing id: %s", s)
	}
	rest = rest[idIdx+len(`"id"`):]
	colon := strings.Index(rest, `"h_`)
	if colon < 0 {
		t.Fatalf("client config host id not h_*: %s", s)
	}
	rest = rest[colon+1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("client config host id unterminated: %s", s)
	}
	return rest[:end]
}

func generateEd25519KeyFile(t *testing.T, path string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	block, err := cryptossh.MarshalPrivateKey(priv, "kauket-test")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir key dir: %v", err)
	}
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	sshPub, err := cryptossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh public key: %v", err)
	}
	pubAuthorized := strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(sshPub)))
	if err := os.WriteFile(path+".pub", []byte(pubAuthorized+"\n"), 0o644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
}

func grepRepo(t *testing.T, dir, term string) []string {
	t.Helper()
	var hits []string
	lowerTerm := strings.ToLower(term)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if isBinaryContent(data) {
			return nil
		}
		if strings.Contains(strings.ToLower(string(data)), lowerTerm) {
			hits = append(hits, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return hits
}

func isBinaryContent(data []byte) bool {
	limit := len(data)
	if limit > 8000 {
		limit = 8000
	}
	for i := 0; i < limit; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}
