package gitstore

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

var requestBranchPattern = regexp.MustCompile(`^request/rq_[a-z2-7]{16}$`)

func clientAuthor() Author {
	return Author{Name: "kauket client", Email: "kauket-h_7j4v6m2q9xk3p8da@h_7j4v6m2q9xk3p8da.local"}
}

func collectRequestBranches(t *testing.T, bareDir string) []string {
	t.Helper()
	bare, err := gogit.PlainOpen(bareDir)
	if err != nil {
		t.Fatalf("open bare: %v", err)
	}
	refs, err := bare.References()
	if err != nil {
		t.Fatalf("refs: %v", err)
	}
	var out []string
	_ = refs.ForEach(func(r *plumbing.Reference) error {
		name := r.Name().String()
		if strings.HasPrefix(name, "refs/heads/request/") {
			out = append(out, strings.TrimPrefix(name, "refs/heads/"))
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func TestPushRequestCreatesBranchWithSingleRequestFile(t *testing.T) {
	remoteURL, bareDir := setupBareRepo(t)
	primary := newStore(t, remoteURL)
	writeFile(t, primary.repoPath, "repo.json", []byte(`{"schema":1}`))
	if err := primary.CommitAndPush(context.Background(), "kauket: initialize store", testAuthor()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	clientDir := t.TempDir()
	cfg := Config{
		RepoPath: filepath.Join(clientDir, "repo"),
		URL:      remoteURL,
		LockPath: filepath.Join(clientDir, "kauket.lock"),
		Now:      fixedNow(),
	}
	client, err := OpenOrClone(context.Background(), cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("client open: %v", err)
	}
	defer client.Close()
	if err := client.Sync(context.Background()); err != nil {
		t.Fatalf("client sync: %v", err)
	}

	const reqID = "rq_m5w8r0qf2p1x9z6a"
	if err := client.PushRequest(context.Background(), reqID, []byte("encrypted-request-bytes"), clientAuthor()); err != nil {
		t.Fatalf("push request: %v", err)
	}

	branches := collectRequestBranches(t, bareDir)
	if len(branches) != 1 || branches[0] != "request/"+reqID {
		t.Fatalf("expected one request branch, got %v", branches)
	}

	bare, err := gogit.PlainOpen(bareDir)
	if err != nil {
		t.Fatalf("open bare: %v", err)
	}
	ref, err := bare.Reference(plumbing.NewBranchReferenceName("request/"+reqID), true)
	if err != nil {
		t.Fatalf("ref: %v", err)
	}
	commit, err := bare.CommitObject(ref.Hash())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if commit.Message != "kauket: submit request" {
		t.Fatalf("unexpected commit message %q", commit.Message)
	}
	tree, err := commit.Tree()
	if err != nil {
		t.Fatalf("tree: %v", err)
	}
	expectedPath := "requests/" + reqID + ".age"
	var fileNames []string
	for _, ent := range tree.Entries {
		fileNames = append(fileNames, ent.Name)
	}
	if len(tree.Entries) != 1 {
		t.Fatalf("expected single top-level dir entry, got %v", fileNames)
	}

	subtree, err := tree.Tree("requests")
	if err != nil {
		t.Fatalf("subtree requests: %v", err)
	}
	if len(subtree.Entries) != 1 || subtree.Entries[0].Name != reqID+".age" {
		t.Fatalf("expected single requests/<id>.age, got %v", subtree.Entries)
	}
	file, err := tree.File(expectedPath)
	if err != nil {
		t.Fatalf("file: %v", err)
	}
	r, err := file.Reader()
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	defer r.Close()
	got, err := readAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, []byte("encrypted-request-bytes")) {
		t.Fatalf("file content mismatch")
	}
}

func TestFetchRequestRefsReturnsContent(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	primary := newStore(t, remoteURL)
	writeFile(t, primary.repoPath, "repo.json", []byte(`{"schema":1}`))
	if err := primary.CommitAndPush(context.Background(), "kauket: initialize store", testAuthor()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	clientDir := t.TempDir()
	cfg := Config{
		RepoPath: filepath.Join(clientDir, "repo"),
		URL:      remoteURL,
		LockPath: filepath.Join(clientDir, "kauket.lock"),
		Now:      fixedNow(),
	}
	client, err := OpenOrClone(context.Background(), cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("client open: %v", err)
	}
	defer client.Close()
	if err := client.Sync(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	const reqID = "rq_aaaaaaaaaaaaaaaa"
	want := []byte("first-request-bytes")
	if err := client.PushRequest(context.Background(), reqID, want, clientAuthor()); err != nil {
		t.Fatalf("push: %v", err)
	}

	refs, err := primary.FetchRequestRefs(context.Background())
	if err != nil {
		t.Fatalf("fetch refs: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d", len(refs))
	}
	ref := refs[0]
	if ref.RequestID != reqID {
		t.Fatalf("request id mismatch: %q", ref.RequestID)
	}
	if ref.Branch != "request/"+reqID {
		t.Fatalf("branch mismatch: %q", ref.Branch)
	}
	if ref.FilePath != "requests/"+reqID+".age" {
		t.Fatalf("file path mismatch: %q", ref.FilePath)
	}
	if !bytes.Equal(ref.Content, want) {
		t.Fatalf("content mismatch")
	}
}

func TestDeleteRequestBranchRemovesRemoteRef(t *testing.T) {
	remoteURL, bareDir := setupBareRepo(t)
	primary := newStore(t, remoteURL)
	writeFile(t, primary.repoPath, "repo.json", []byte(`{"schema":1}`))
	if err := primary.CommitAndPush(context.Background(), "kauket: initialize store", testAuthor()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	clientDir := t.TempDir()
	cfg := Config{
		RepoPath: filepath.Join(clientDir, "repo"),
		URL:      remoteURL,
		LockPath: filepath.Join(clientDir, "kauket.lock"),
		Now:      fixedNow(),
	}
	client, err := OpenOrClone(context.Background(), cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("client open: %v", err)
	}
	defer client.Close()
	if err := client.Sync(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	const reqID = "rq_bbbbbbbbbbbbbbbb"
	if err := client.PushRequest(context.Background(), reqID, []byte("data"), clientAuthor()); err != nil {
		t.Fatalf("push: %v", err)
	}
	branches := collectRequestBranches(t, bareDir)
	if len(branches) != 1 {
		t.Fatalf("expected one branch before delete, got %v", branches)
	}

	if err := primary.DeleteRequestBranch(context.Background(), reqID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	branches = collectRequestBranches(t, bareDir)
	if len(branches) != 0 {
		t.Fatalf("expected no request branches after delete, got %v", branches)
	}
	refs, err := primary.FetchRequestRefs(context.Background())
	if err != nil {
		t.Fatalf("fetch after delete: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("expected no refs after delete, got %v", refs)
	}
}

func TestMultipleRequestsRoundTripAndDelete(t *testing.T) {
	remoteURL, bareDir := setupBareRepo(t)
	primary := newStore(t, remoteURL)
	writeFile(t, primary.repoPath, "repo.json", []byte(`{"schema":1}`))
	if err := primary.CommitAndPush(context.Background(), "kauket: initialize store", testAuthor()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	clientDir := t.TempDir()
	cfg := Config{
		RepoPath: filepath.Join(clientDir, "repo"),
		URL:      remoteURL,
		LockPath: filepath.Join(clientDir, "kauket.lock"),
		Now:      fixedNow(),
	}
	client, err := OpenOrClone(context.Background(), cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("client open: %v", err)
	}
	defer client.Close()
	if err := client.Sync(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	ids := []string{
		"rq_2qaaaaaaaaaaaaaa",
		"rq_3qaaaaaaaaaaaaaa",
		"rq_4qaaaaaaaaaaaaaa",
	}
	for i, id := range ids {
		payload := []byte("payload-" + id + "-" + itoa(i))
		if err := client.PushRequest(context.Background(), id, payload, clientAuthor()); err != nil {
			t.Fatalf("push %s: %v", id, err)
		}
	}

	branches := collectRequestBranches(t, bareDir)
	if len(branches) != len(ids) {
		t.Fatalf("expected %d branches, got %v", len(ids), branches)
	}
	for _, b := range branches {
		if !requestBranchPattern.MatchString(b) {
			t.Fatalf("branch %q does not match request/rq_[a-z2-7]{16}", b)
		}
	}

	refs, err := primary.FetchRequestRefs(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(refs) != len(ids) {
		t.Fatalf("expected %d refs, got %d", len(ids), len(refs))
	}
	got := map[string][]byte{}
	for _, r := range refs {
		got[r.RequestID] = r.Content
		if r.FilePath != "requests/"+r.RequestID+".age" {
			t.Fatalf("file path %q unexpected", r.FilePath)
		}
	}
	for i, id := range ids {
		want := []byte("payload-" + id + "-" + itoa(i))
		if !bytes.Equal(got[id], want) {
			t.Fatalf("content mismatch for %s: got %q want %q", id, got[id], want)
		}
	}

	if err := primary.DeleteRequestBranch(context.Background(), ids[1]); err != nil {
		t.Fatalf("delete: %v", err)
	}

	branches = collectRequestBranches(t, bareDir)
	if len(branches) != 2 {
		t.Fatalf("expected 2 branches after delete, got %v", branches)
	}
	for _, b := range branches {
		if b == "request/"+ids[1] {
			t.Fatalf("deleted branch still present: %v", branches)
		}
	}
}

func TestPushRequestRejectsBadID(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	s := newStore(t, remoteURL)
	writeFile(t, s.repoPath, "repo.json", []byte(`{"schema":1}`))
	if err := s.CommitAndPush(context.Background(), "kauket: initialize store", testAuthor()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err := s.PushRequest(context.Background(), "machine2", []byte("x"), clientAuthor())
	if err == nil {
		t.Fatalf("expected error for non-rq_ prefixed id")
	}
}

func TestDeleteRequestBranchRejectsBadID(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	s := newStore(t, remoteURL)
	err := s.DeleteRequestBranch(context.Background(), "machine2")
	if err == nil {
		t.Fatalf("expected error for bad id")
	}
}

func TestRequestBranchNameLeakScan(t *testing.T) {
	remoteURL, bareDir := setupBareRepo(t)
	primary := newStore(t, remoteURL)
	writeFile(t, primary.repoPath, "repo.json", []byte(`{"schema":1}`))
	if err := primary.CommitAndPush(context.Background(), "kauket: initialize store", testAuthor()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	clientDir := t.TempDir()
	cfg := Config{
		RepoPath: filepath.Join(clientDir, "repo"),
		URL:      remoteURL,
		LockPath: filepath.Join(clientDir, "kauket.lock"),
		Now:      fixedNow(),
	}
	client, err := OpenOrClone(context.Background(), cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer client.Close()
	if err := client.Sync(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	const reqID = "rq_zzzzzzzzzzzzzzzz"
	if err := client.PushRequest(context.Background(), reqID, []byte("data"), clientAuthor()); err != nil {
		t.Fatalf("push: %v", err)
	}
	branches := collectRequestBranches(t, bareDir)
	for _, b := range branches {
		for _, bad := range disallowedWordlist {
			if strings.Contains(strings.ToLower(b), bad) {
				t.Fatalf("disallowed word %q in branch %q", bad, b)
			}
		}
		if !requestBranchPattern.MatchString(b) {
			t.Fatalf("branch %q does not match expected request/rq_[a-z2-7]{16}", b)
		}
	}
}

func TestPushRequestSwitchesBackToMain(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	primary := newStore(t, remoteURL)
	writeFile(t, primary.repoPath, "repo.json", []byte(`{"schema":1}`))
	if err := primary.CommitAndPush(context.Background(), "kauket: initialize store", testAuthor()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	clientDir := t.TempDir()
	cfg := Config{
		RepoPath: filepath.Join(clientDir, "repo"),
		URL:      remoteURL,
		LockPath: filepath.Join(clientDir, "kauket.lock"),
		Now:      fixedNow(),
	}
	client, err := OpenOrClone(context.Background(), cfg, SelectTransport(remoteURL, ""))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer client.Close()
	if err := client.Sync(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	const reqID = "rq_cccccccccccccccc"
	if err := client.PushRequest(context.Background(), reqID, []byte("payload"), clientAuthor()); err != nil {
		t.Fatalf("push request: %v", err)
	}

	repo, err := gogit.PlainOpen(client.repoPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	head, err := repo.Head()
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if head.Name() != plumbing.NewBranchReferenceName("main") {
		t.Fatalf("expected HEAD on main, got %s", head.Name())
	}
}

func TestErrNoRequestFileReturnedWhenTreeLacksRequest(t *testing.T) {
	remoteURL, _ := setupBareRepo(t)
	primary := newStore(t, remoteURL)
	writeFile(t, primary.repoPath, "repo.json", []byte(`{"schema":1}`))
	if err := primary.CommitAndPush(context.Background(), "kauket: initialize store", testAuthor()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	repo, err := gogit.PlainOpen(primary.repoPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	headRef, err := repo.Head()
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	newRef := plumbing.NewHashReference(plumbing.NewRemoteReferenceName("origin", "request/rq_dddddddddddddddd"), headRef.Hash())
	if err := repo.Storer.SetReference(newRef); err != nil {
		t.Fatalf("set ref: %v", err)
	}

	_, _, err = loadRequestFile(repo, headRef.Hash(), "rq_dddddddddddddddd")
	if !errors.Is(err, ErrNoRequestFile) {
		t.Fatalf("expected ErrNoRequestFile, got %v", err)
	}
}

func readAll(r interface{ Read(p []byte) (int, error) }) ([]byte, error) {
	var out []byte
	buf := make([]byte, 1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return out, nil
			}
			return out, err
		}
	}
}
