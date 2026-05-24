package gitstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

const adminTestEmail = "gonzaloab@gmail.com"

var disallowedWordlist = []string{
	"ssh",
	"aws",
	"cloudflare",
	"headscale",
	"tailscale",
	"grafana",
	"r730xd",
	"kaiser",
	"machine2",
	"hostname",
	"private_key",
	"credentials",
}

func setupBareRepo(t *testing.T) (remoteURL string, bareDir string) {
	t.Helper()
	bare := t.TempDir()
	repo, err := gogit.PlainInit(bare, true)
	if err != nil {
		t.Fatalf("init bare: %v", err)
	}
	headRef := plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.NewBranchReferenceName("main"))
	if err := repo.Storer.SetReference(headRef); err != nil {
		t.Fatalf("set bare HEAD to main: %v", err)
	}
	return "file://" + bare, bare
}

func testAuthor() Author {
	return Author{Name: "Gonzalo Alvarez", Email: adminTestEmail}
}

func fixedNow() func() time.Time {
	t := time.Date(2026, time.May, 24, 12, 0, 0, 0, time.UTC)
	return func() time.Time {
		t = t.Add(time.Second)
		return t
	}
}

func newStore(t *testing.T, remoteURL string) *Store {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{
		RepoPath: filepath.Join(dir, "repo"),
		URL:      remoteURL,
		LockPath: filepath.Join(dir, "kauket.lock"),
		Now:      fixedNow(),
	}
	s, err := OpenOrClone(context.Background(), cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("OpenOrClone: %v", err)
	}
	t.Cleanup(func() {
		_ = s.Close()
	})
	return s
}

func writeFile(t *testing.T, repoPath, rel string, data []byte) {
	t.Helper()
	abs := filepath.Join(repoPath, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(abs, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func TestOpenOrCloneFreshCloneFromBareRemote(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	s := newStore(t, remoteURL)
	if _, err := os.Stat(filepath.Join(s.repoPath, ".git")); err != nil {
		t.Fatalf("expected .git after clone: %v", err)
	}
}

func TestOpenOrCloneTwiceReopens(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	dir := t.TempDir()
	cfg := Config{
		RepoPath: filepath.Join(dir, "repo"),
		URL:      remoteURL,
		LockPath: filepath.Join(dir, "kauket.lock"),
		Now:      fixedNow(),
	}
	s1, err := OpenOrClone(context.Background(), cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close 1: %v", err)
	}
	s2, err := OpenOrClone(context.Background(), cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatalf("close 2: %v", err)
	}
}

func TestCommitAndPushAndSyncFromSecondClone(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	primary := newStore(t, remoteURL)

	writeFile(t, primary.repoPath, "repo.json", []byte(`{"schema":1}`))
	writeFile(t, primary.repoPath, "admin/vault.age", []byte("dummy-ciphertext"))

	ctx := context.Background()
	if err := primary.CommitAndPush(ctx, "kauket: initialize store", testAuthor()); err != nil {
		t.Fatalf("commit and push: %v", err)
	}

	secondaryDir := t.TempDir()
	cfg := Config{
		RepoPath: filepath.Join(secondaryDir, "repo"),
		URL:      remoteURL,
		LockPath: filepath.Join(secondaryDir, "kauket.lock"),
		Now:      fixedNow(),
	}
	secondary, err := OpenOrClone(ctx, cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("open secondary: %v", err)
	}
	defer secondary.Close()
	if err := secondary.Sync(ctx); err != nil {
		t.Fatalf("sync secondary: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(secondary.repoPath, "repo.json"))
	if err != nil {
		t.Fatalf("read repo.json: %v", err)
	}
	if string(got) != `{"schema":1}` {
		t.Fatalf("unexpected repo.json: %q", string(got))
	}
}

func TestCommitAndPushCleanIsNoop(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	s := newStore(t, remoteURL)
	writeFile(t, s.repoPath, "repo.json", []byte(`{"schema":1}`))
	if err := s.CommitAndPush(context.Background(), "kauket: initialize store", testAuthor()); err != nil {
		t.Fatalf("initial commit: %v", err)
	}
	if err := s.CommitAndPush(context.Background(), "kauket: update vault", testAuthor()); err != nil {
		t.Fatalf("clean second commit: %v", err)
	}
}

func TestGenericCommitMessageRoundTripNoLeakage(t *testing.T) {
	remoteURL, bareDir := setupBareRepo(t)
	s := newStore(t, remoteURL)
	writeFile(t, s.repoPath, "repo.json", []byte(`{"schema":1}`))
	writeFile(t, s.repoPath, "admin/vault.age", []byte("ct-a"))
	writeFile(t, s.repoPath, "bundles/h_7j4v6m2q9xk3p8da.age", []byte("ct-b"))

	messages := []string{
		"kauket: initialize store",
		"kauket: update vault",
		"kauket: update bundle",
		"kauket: approve request",
	}
	ctx := context.Background()
	if err := s.CommitAndPush(ctx, messages[0], testAuthor()); err != nil {
		t.Fatalf("commit 1: %v", err)
	}
	writeFile(t, s.repoPath, "admin/vault.age", []byte("ct-a2"))
	if err := s.CommitAndPush(ctx, messages[1], testAuthor()); err != nil {
		t.Fatalf("commit 2: %v", err)
	}
	writeFile(t, s.repoPath, "bundles/h_7j4v6m2q9xk3p8da.age", []byte("ct-b2"))
	if err := s.CommitAndPush(ctx, messages[2], testAuthor()); err != nil {
		t.Fatalf("commit 3: %v", err)
	}
	writeFile(t, s.repoPath, "admin/vault.age", []byte("ct-a3"))
	if err := s.CommitAndPush(ctx, messages[3], testAuthor()); err != nil {
		t.Fatalf("commit 4: %v", err)
	}

	bareRepo, err := gogit.PlainOpen(bareDir)
	if err != nil {
		t.Fatalf("open bare: %v", err)
	}
	ref, err := bareRepo.Reference(plumbing.NewBranchReferenceName("main"), true)
	if err != nil {
		t.Fatalf("resolve main on bare: %v", err)
	}
	iter, err := bareRepo.Log(&gogit.LogOptions{From: ref.Hash()})
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	var seenMessages []string
	err = iter.ForEach(func(c *object.Commit) error {
		seenMessages = append(seenMessages, c.Message)
		for _, bad := range disallowedWordlist {
			if strings.Contains(strings.ToLower(c.Message), bad) {
				t.Fatalf("disallowed word %q in commit message %q", bad, c.Message)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk log: %v", err)
	}
	if len(seenMessages) != len(messages) {
		t.Fatalf("expected %d commits, got %d", len(messages), len(seenMessages))
	}
	for _, m := range messages {
		if !containsExact(seenMessages, m) {
			t.Fatalf("expected commit message %q in log %v", m, seenMessages)
		}
	}
}

func containsExact(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func TestSyncOnEmptyRemoteIsNoop(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	s := newStore(t, remoteURL)
	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("sync on empty: %v", err)
	}
}

func TestSyncAfterRemotePushPullsNewCommits(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	primary := newStore(t, remoteURL)
	writeFile(t, primary.repoPath, "repo.json", []byte(`{"schema":1}`))
	if err := primary.CommitAndPush(context.Background(), "kauket: initialize store", testAuthor()); err != nil {
		t.Fatalf("primary init: %v", err)
	}

	secondaryDir := t.TempDir()
	cfg := Config{
		RepoPath: filepath.Join(secondaryDir, "repo"),
		URL:      remoteURL,
		LockPath: filepath.Join(secondaryDir, "kauket.lock"),
		Now:      fixedNow(),
	}
	secondary, err := OpenOrClone(context.Background(), cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("open secondary: %v", err)
	}
	defer secondary.Close()

	writeFile(t, primary.repoPath, "admin/vault.age", []byte("v1"))
	if err := primary.CommitAndPush(context.Background(), "kauket: update vault", testAuthor()); err != nil {
		t.Fatalf("primary second commit: %v", err)
	}

	before, _ := os.Stat(filepath.Join(secondary.repoPath, "admin", "vault.age"))
	if before != nil {
		t.Fatalf("secondary should not have vault.age before sync")
	}
	if err := secondary.Sync(context.Background()); err != nil {
		t.Fatalf("secondary sync: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(secondary.repoPath, "admin", "vault.age"))
	if err != nil {
		t.Fatalf("read vault.age after sync: %v", err)
	}
	if !bytes.Equal(got, []byte("v1")) {
		t.Fatalf("expected v1, got %q", string(got))
	}
}

func TestCommitAndPushNonFastForwardSentinel(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	primary := newStore(t, remoteURL)
	writeFile(t, primary.repoPath, "repo.json", []byte(`{"schema":1}`))
	if err := primary.CommitAndPush(context.Background(), "kauket: initialize store", testAuthor()); err != nil {
		t.Fatalf("primary init: %v", err)
	}

	secondaryDir := t.TempDir()
	cfg := Config{
		RepoPath: filepath.Join(secondaryDir, "repo"),
		URL:      remoteURL,
		LockPath: filepath.Join(secondaryDir, "kauket.lock"),
		Now:      fixedNow(),
	}
	secondary, err := OpenOrClone(context.Background(), cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("open secondary: %v", err)
	}
	defer secondary.Close()

	writeFile(t, primary.repoPath, "admin/vault.age", []byte("from-primary"))
	if err := primary.CommitAndPush(context.Background(), "kauket: update vault", testAuthor()); err != nil {
		t.Fatalf("primary push: %v", err)
	}

	writeFile(t, secondary.repoPath, "admin/vault.age", []byte("from-secondary"))
	err = secondary.CommitAndPush(context.Background(), "kauket: update vault", testAuthor())
	if !errors.Is(err, ErrNonFastForward) {
		t.Fatalf("expected ErrNonFastForward, got %v", err)
	}

	syncedVault, readErr := os.ReadFile(filepath.Join(secondary.repoPath, "admin", "vault.age"))
	if readErr != nil {
		t.Fatalf("read vault.age after non-ff: %v", readErr)
	}
	if !bytes.Equal(syncedVault, []byte("from-primary")) {
		t.Fatalf("expected primary value after auto-sync, got %q", string(syncedVault))
	}
}

func TestLockContentionReturnsErrLocked(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	dir := t.TempDir()
	cfg := Config{
		RepoPath: filepath.Join(dir, "repo"),
		URL:      remoteURL,
		LockPath: filepath.Join(dir, "kauket.lock"),
		Now:      fixedNow(),
	}
	s1, err := OpenOrClone(context.Background(), cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	defer s1.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	cfg2 := Config{
		RepoPath: filepath.Join(dir, "repo2"),
		URL:      remoteURL,
		LockPath: cfg.LockPath,
		Now:      fixedNow(),
	}
	_, err = OpenOrClone(ctx, cfg2, SelectTransport(remoteURL, ""))
	if err == nil {
		t.Fatalf("expected lock error, got nil")
	}
	if !errors.Is(err, ErrLocked) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected ErrLocked or DeadlineExceeded, got %v", err)
	}
}

func TestConcurrentOpenOrCloneOneWinsOneLoses(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "kauket.lock")

	type result struct {
		store *Store
		err   error
	}
	var wg sync.WaitGroup
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			cfg := Config{
				RepoPath: filepath.Join(dir, "repo", "g", "g", "g", "x"+itoa(idx)),
				URL:      remoteURL,
				LockPath: lockPath,
				Now:      fixedNow(),
			}
			s, err := OpenOrClone(ctx, cfg, SelectTransport(remoteURL, ""))
			results <- result{store: s, err: err}
		}()
	}
	wg.Wait()
	close(results)
	var wins, losses int
	for r := range results {
		if r.err != nil {
			losses++
			if !errors.Is(r.err, ErrLocked) && !errors.Is(r.err, context.DeadlineExceeded) {
				t.Fatalf("unexpected error from loser: %v", r.err)
			}
			continue
		}
		wins++
		_ = r.store.Close()
	}
	if wins == 0 || losses == 0 {
		t.Fatalf("expected one winner and one loser, got wins=%d losses=%d", wins, losses)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

func TestCloseReleasesLockAllowsReacquire(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	dir := t.TempDir()
	cfg := Config{
		RepoPath: filepath.Join(dir, "repo"),
		URL:      remoteURL,
		LockPath: filepath.Join(dir, "kauket.lock"),
		Now:      fixedNow(),
	}
	s1, err := OpenOrClone(context.Background(), cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close 1: %v", err)
	}
	s2, err := OpenOrClone(context.Background(), cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("second open after close: %v", err)
	}
	_ = s2.Close()
}

func TestSelectTransportFileURLReturnsNilAuth(t *testing.T) {
	tr := SelectTransport("file:///tmp/foo", "any-token")
	if _, ok := tr.(FileURLTransport); !ok {
		t.Fatalf("expected FileURLTransport, got %T", tr)
	}
	if tr.Auth() != nil {
		t.Fatalf("expected nil auth for file URL, got %v", tr.Auth())
	}
}

func TestSelectTransportHTTPSReturnsBasicAuth(t *testing.T) {
	tr := SelectTransport("https://github.com/foo/bar.git", "ghs_abc")
	if _, ok := tr.(HTTPSTokenTransport); !ok {
		t.Fatalf("expected HTTPSTokenTransport, got %T", tr)
	}
	if tr.Auth() == nil {
		t.Fatalf("expected non-nil auth for https with token")
	}
}

func TestHTTPSTransportEmptyTokenReturnsNilAuth(t *testing.T) {
	tr := HTTPSTokenTransport{}
	if tr.Auth() != nil {
		t.Fatalf("expected nil auth when token empty")
	}
}

func TestBranchScanOnMainOnlyMain(t *testing.T) {
	remoteURL, bareDir := setupBareRepo(t)
	s := newStore(t, remoteURL)
	writeFile(t, s.repoPath, "repo.json", []byte(`{"schema":1}`))
	if err := s.CommitAndPush(context.Background(), "kauket: initialize store", testAuthor()); err != nil {
		t.Fatalf("commit: %v", err)
	}
	bare, err := gogit.PlainOpen(bareDir)
	if err != nil {
		t.Fatalf("open bare: %v", err)
	}
	refs, err := bare.References()
	if err != nil {
		t.Fatalf("refs: %v", err)
	}
	var branches []string
	_ = refs.ForEach(func(r *plumbing.Reference) error {
		name := r.Name().String()
		if strings.HasPrefix(name, "refs/heads/") {
			branches = append(branches, strings.TrimPrefix(name, "refs/heads/"))
		}
		return nil
	})
	if len(branches) != 1 || branches[0] != "main" {
		t.Fatalf("expected only main, got %v", branches)
	}
}

func TestCommitAuthorMetadataLeakScan(t *testing.T) {
	remoteURL, bareDir := setupBareRepo(t)
	s := newStore(t, remoteURL)
	writeFile(t, s.repoPath, "repo.json", []byte(`{"schema":1}`))
	if err := s.CommitAndPush(context.Background(), "kauket: initialize store", testAuthor()); err != nil {
		t.Fatalf("commit: %v", err)
	}

	bare, err := gogit.PlainOpen(bareDir)
	if err != nil {
		t.Fatalf("open bare: %v", err)
	}
	ref, err := bare.Reference(plumbing.NewBranchReferenceName("main"), true)
	if err != nil {
		t.Fatalf("ref: %v", err)
	}
	commit, err := bare.CommitObject(ref.Hash())
	if err != nil {
		t.Fatalf("commit object: %v", err)
	}
	for _, bad := range disallowedWordlist {
		if strings.Contains(strings.ToLower(commit.Author.Name), bad) {
			t.Fatalf("disallowed word %q in author name %q", bad, commit.Author.Name)
		}
		if strings.Contains(strings.ToLower(commit.Author.Email), bad) {
			t.Fatalf("disallowed word %q in author email %q", bad, commit.Author.Email)
		}
	}
}

func TestNowInjectableDefault(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	dir := t.TempDir()
	cfg := Config{
		RepoPath: filepath.Join(dir, "repo"),
		URL:      remoteURL,
		LockPath: filepath.Join(dir, "kauket.lock"),
	}
	s, err := OpenOrClone(context.Background(), cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if s.now == nil {
		t.Fatalf("now should default to non-nil")
	}
	before := time.Now().Add(-time.Second)
	after := time.Now().Add(time.Second)
	got := s.now()
	if got.Before(before) || got.After(after) {
		t.Fatalf("default now returned %v outside [%v, %v]", got, before, after)
	}
}

func TestEmptyConfigFieldsRejected(t *testing.T) {
	for name, cfg := range map[string]Config{
		"empty repo path": {URL: "file:///nope", LockPath: "/tmp/x.lock"},
		"empty url":       {RepoPath: "/tmp/r", LockPath: "/tmp/x.lock"},
		"empty lock":      {RepoPath: "/tmp/r", URL: "file:///nope"},
	} {
		_, err := OpenOrClone(context.Background(), cfg, FileURLTransport{})
		if err == nil {
			t.Fatalf("[%s] expected error for empty config field", name)
		}
	}
}

func TestReadRawFileFromRepoMatches(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	s := newStore(t, remoteURL)
	writeFile(t, s.repoPath, "repo.json", []byte(`{"schema":1}`))
	if err := s.CommitAndPush(context.Background(), "kauket: initialize store", testAuthor()); err != nil {
		t.Fatalf("commit: %v", err)
	}
	repo, err := gogit.PlainOpen(s.repoPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	f, err := wt.Filesystem.Open("repo.json")
	if err != nil {
		t.Fatalf("open repo.json from worktree: %v", err)
	}
	defer f.Close()
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, []byte(`{"schema":1}`)) {
		t.Fatalf("unexpected: %q", string(got))
	}
}

func TestRetryAfterNonFastForwardSucceedsOnSecondAttempt(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	primary := newStore(t, remoteURL)
	writeFile(t, primary.repoPath, "repo.json", []byte(`{"schema":1}`))
	if err := primary.CommitAndPush(context.Background(), "kauket: initialize store", testAuthor()); err != nil {
		t.Fatalf("primary init: %v", err)
	}

	secondaryDir := t.TempDir()
	cfg := Config{
		RepoPath: filepath.Join(secondaryDir, "repo"),
		URL:      remoteURL,
		LockPath: filepath.Join(secondaryDir, "kauket.lock"),
		Now:      fixedNow(),
	}
	secondary, err := OpenOrClone(context.Background(), cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("open secondary: %v", err)
	}
	defer secondary.Close()

	writeFile(t, primary.repoPath, "admin/vault.age", []byte("primary"))
	if err := primary.CommitAndPush(context.Background(), "kauket: update vault", testAuthor()); err != nil {
		t.Fatalf("primary push: %v", err)
	}

	writeFile(t, secondary.repoPath, "admin/vault.age", []byte("secondary"))
	err = secondary.CommitAndPush(context.Background(), "kauket: update vault", testAuthor())
	if !errors.Is(err, ErrNonFastForward) {
		t.Fatalf("expected ErrNonFastForward first try, got %v", err)
	}

	writeFile(t, secondary.repoPath, "admin/vault.age", []byte("secondary-retry"))
	if err := secondary.CommitAndPush(context.Background(), "kauket: update vault", testAuthor()); err != nil {
		t.Fatalf("retry push: %v", err)
	}

	bare, err := gogit.PlainOpen(strings.TrimPrefix(remoteURL, "file://"))
	if err != nil {
		t.Fatalf("open bare: %v", err)
	}
	ref, err := bare.Reference(plumbing.NewBranchReferenceName("main"), true)
	if err != nil {
		t.Fatalf("ref: %v", err)
	}
	commit, err := bare.CommitObject(ref.Hash())
	if err != nil {
		t.Fatalf("commit object: %v", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		t.Fatalf("tree: %v", err)
	}
	entry, err := tree.File("admin/vault.age")
	if err != nil {
		t.Fatalf("file: %v", err)
	}
	r, err := entry.Reader()
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(data, []byte("secondary-retry")) {
		t.Fatalf("expected secondary-retry, got %q", string(data))
	}
}

func TestRefSpecValuesAreExpected(t *testing.T) {
	if mainFetchRefSpec != "+refs/heads/main:refs/remotes/origin/main" {
		t.Fatalf("mainFetchRefSpec unexpected: %q", mainFetchRefSpec)
	}
	if config.RefSpec(requestFetchRefSpec).Validate() != nil {
		t.Fatalf("requestFetchRefSpec invalid: %q", requestFetchRefSpec)
	}
}
