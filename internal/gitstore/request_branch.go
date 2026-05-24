package gitstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
)

const (
	requestBranchPrefix     = "request/"
	requestRemoteRefsPrefix = "refs/remotes/origin/request/"
	requestIDPrefix         = "rq_"
	requestsDir             = "requests"
	requestFileExt          = ".age"
)

var requestFetchRefSpec = "+refs/heads/request" + "/" + "*:refs/remotes/origin/request" + "/" + "*"

type RequestRef struct {
	Branch    string
	RequestID string
	FilePath  string
	Content   []byte
}

func (s *Store) PushRequest(ctx context.Context, requestID string, data []byte, author Author) error {
	if !strings.HasPrefix(requestID, requestIDPrefix) {
		return fmt.Errorf("kauket: request id must start with %q", requestIDPrefix)
	}
	repo, err := s.repo()
	if err != nil {
		return err
	}

	commitHash, err := writeOrphanRequestCommit(repo, requestID, data, author, s.now())
	if err != nil {
		return err
	}

	branch := requestBranchPrefix + requestID
	branchRef := plumbing.NewHashReference(plumbing.NewBranchReferenceName(branch), commitHash)
	if err := repo.Storer.SetReference(branchRef); err != nil {
		return fmt.Errorf("kauket: set request branch ref: %w", err)
	}

	pushSpec := config.RefSpec(fmt.Sprintf("refs/heads/%s:refs/heads/%s", branch, branch))
	pushErr := repo.PushContext(ctx, &gogit.PushOptions{
		RemoteName: remoteName,
		RefSpecs:   []config.RefSpec{pushSpec},
		Auth:       s.auth,
	})
	if pushErr != nil && !errors.Is(pushErr, gogit.NoErrAlreadyUpToDate) {
		_ = repo.Storer.RemoveReference(plumbing.NewBranchReferenceName(branch))
		return fmt.Errorf("kauket: push request branch: %w", pushErr)
	}

	if err := repo.Storer.RemoveReference(plumbing.NewBranchReferenceName(branch)); err != nil && !errors.Is(err, plumbing.ErrReferenceNotFound) {
		return fmt.Errorf("kauket: remove local request branch ref: %w", err)
	}
	return nil
}

func writeOrphanRequestCommit(repo *gogit.Repository, requestID string, data []byte, author Author, when time.Time) (plumbing.Hash, error) {
	st := repo.Storer
	blob := st.NewEncodedObject()
	blob.SetType(plumbing.BlobObject)
	bw, err := blob.Writer()
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("kauket: blob writer: %w", err)
	}
	if _, err := io.Copy(bw, bytes.NewReader(data)); err != nil {
		_ = bw.Close()
		return plumbing.ZeroHash, fmt.Errorf("kauket: blob write: %w", err)
	}
	if err := bw.Close(); err != nil {
		return plumbing.ZeroHash, fmt.Errorf("kauket: blob close: %w", err)
	}
	blobHash, err := st.SetEncodedObject(blob)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("kauket: store blob: %w", err)
	}

	innerTree := object.Tree{
		Entries: []object.TreeEntry{{
			Name: requestID + requestFileExt,
			Mode: filemode.Regular,
			Hash: blobHash,
		}},
	}
	innerTreeHash, err := storeTree(st, &innerTree)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	rootTree := object.Tree{
		Entries: []object.TreeEntry{{
			Name: requestsDir,
			Mode: filemode.Dir,
			Hash: innerTreeHash,
		}},
	}
	rootTreeHash, err := storeTree(st, &rootTree)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	sig := object.Signature{
		Name:  author.Name,
		Email: author.Email,
		When:  when,
	}
	return storeCommit(st, rootTreeHash, sig)
}

func storeTree(st storer.EncodedObjectStorer, tree *object.Tree) (plumbing.Hash, error) {
	obj := st.NewEncodedObject()
	if err := tree.Encode(obj); err != nil {
		return plumbing.ZeroHash, fmt.Errorf("kauket: encode tree: %w", err)
	}
	h, err := st.SetEncodedObject(obj)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("kauket: store tree: %w", err)
	}
	return h, nil
}

func storeCommit(st storer.EncodedObjectStorer, treeHash plumbing.Hash, sig object.Signature) (plumbing.Hash, error) {
	commit := object.Commit{
		Author:       sig,
		Committer:    sig,
		Message:      "kauket: submit request",
		TreeHash:     treeHash,
		ParentHashes: nil,
	}
	obj := st.NewEncodedObject()
	if err := commit.Encode(obj); err != nil {
		return plumbing.ZeroHash, fmt.Errorf("kauket: encode commit: %w", err)
	}
	h, err := st.SetEncodedObject(obj)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("kauket: store commit: %w", err)
	}
	return h, nil
}

func (s *Store) FetchRequestRefs(ctx context.Context) ([]RequestRef, error) {
	repo, err := s.repo()
	if err != nil {
		return nil, err
	}
	fetchErr := repo.FetchContext(ctx, &gogit.FetchOptions{
		RemoteName: remoteName,
		RefSpecs:   []config.RefSpec{config.RefSpec(requestFetchRefSpec)},
		Auth:       s.auth,
	})
	if fetchErr != nil && !errors.Is(fetchErr, gogit.NoErrAlreadyUpToDate) {
		return nil, fmt.Errorf("kauket: fetch request refs: %w", fetchErr)
	}

	refs, err := repo.References()
	if err != nil {
		return nil, fmt.Errorf("kauket: list refs: %w", err)
	}

	var out []RequestRef
	refsErr := refs.ForEach(func(ref *plumbing.Reference) error {
		name := ref.Name().String()
		if !strings.HasPrefix(name, requestRemoteRefsPrefix) {
			return nil
		}
		shortBranch := strings.TrimPrefix(name, "refs/remotes/origin/")
		requestID := strings.TrimPrefix(shortBranch, requestBranchPrefix)
		if !strings.HasPrefix(requestID, requestIDPrefix) {
			return nil
		}
		content, fp, err := loadRequestFile(repo, ref.Hash(), requestID)
		if err != nil {
			return err
		}
		out = append(out, RequestRef{
			Branch:    shortBranch,
			RequestID: requestID,
			FilePath:  fp,
			Content:   content,
		})
		return nil
	})
	if refsErr != nil {
		return nil, refsErr
	}
	return out, nil
}

func loadRequestFile(repo *gogit.Repository, hash plumbing.Hash, requestID string) ([]byte, string, error) {
	commit, err := repo.CommitObject(hash)
	if err != nil {
		return nil, "", fmt.Errorf("kauket: load commit %s: %w", hash, err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, "", fmt.Errorf("kauket: load tree: %w", err)
	}
	wantPath := path.Join(requestsDir, requestID+requestFileExt)
	entry, err := tree.File(wantPath)
	if err != nil {
		if errors.Is(err, object.ErrFileNotFound) {
			return nil, wantPath, ErrNoRequestFile
		}
		return nil, wantPath, fmt.Errorf("kauket: open request file %s: %w", wantPath, err)
	}
	r, err := entry.Reader()
	if err != nil {
		return nil, wantPath, fmt.Errorf("kauket: read request file %s: %w", wantPath, err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, wantPath, fmt.Errorf("kauket: read request bytes %s: %w", wantPath, err)
	}
	return data, wantPath, nil
}

func (s *Store) DeleteRequestBranch(ctx context.Context, requestID string) error {
	if !strings.HasPrefix(requestID, requestIDPrefix) {
		return fmt.Errorf("kauket: request id must start with %q", requestIDPrefix)
	}
	repo, err := s.repo()
	if err != nil {
		return err
	}
	branch := requestBranchPrefix + requestID
	deleteSpec := config.RefSpec(fmt.Sprintf(":refs/heads/%s", branch))
	err = repo.PushContext(ctx, &gogit.PushOptions{
		RemoteName: remoteName,
		RefSpecs:   []config.RefSpec{deleteSpec},
		Auth:       s.auth,
	})
	if err != nil && !errors.Is(err, gogit.NoErrAlreadyUpToDate) {
		return fmt.Errorf("kauket: delete remote request branch: %w", err)
	}
	if err := repo.Storer.RemoveReference(plumbing.NewRemoteReferenceName(remoteName, branch)); err != nil && !errors.Is(err, plumbing.ErrReferenceNotFound) {
		return fmt.Errorf("kauket: remove local tracking ref: %w", err)
	}
	if err := repo.Storer.RemoveReference(plumbing.NewBranchReferenceName(branch)); err != nil && !errors.Is(err, plumbing.ErrReferenceNotFound) {
		return fmt.Errorf("kauket: remove local branch ref: %w", err)
	}
	return nil
}
