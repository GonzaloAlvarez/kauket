package gitstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/gofrs/flock"
)

const (
	remoteName       = "origin"
	defaultBranch    = "main"
	mainFetchRefSpec = "+refs/heads/main:refs/remotes/origin/main"
)

type Author struct {
	Name  string
	Email string
}

type Config struct {
	RepoPath string
	URL      string
	LockPath string
	Now      func() time.Time
}

type Store struct {
	repoPath string
	url      string
	lockPath string
	auth     transport.AuthMethod
	lock     *flock.Flock
	now      func() time.Time
}

func OpenOrClone(ctx context.Context, cfg Config, t Transport) (*Store, error) {
	if cfg.RepoPath == "" {
		return nil, errors.New("kauket: gitstore Config.RepoPath is empty")
	}
	if cfg.URL == "" {
		return nil, errors.New("kauket: gitstore Config.URL is empty")
	}
	if cfg.LockPath == "" {
		return nil, errors.New("kauket: gitstore Config.LockPath is empty")
	}
	if t == nil {
		t = SelectTransport(cfg.URL, "")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	fl, err := acquireLock(ctx, cfg.LockPath)
	if err != nil {
		return nil, err
	}

	auth := t.Auth()
	if strings.HasPrefix(cfg.URL, "file://") {
		auth = nil
	}

	gitDir := filepath.Join(cfg.RepoPath, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			_ = fl.Unlock()
			return nil, fmt.Errorf("kauket: stat .git: %w", err)
		}
		if err := os.MkdirAll(cfg.RepoPath, 0o700); err != nil {
			_ = fl.Unlock()
			return nil, fmt.Errorf("kauket: mkdir repo path: %w", err)
		}
		if _, err := gogit.PlainCloneContext(ctx, cfg.RepoPath, false, &gogit.CloneOptions{
			URL:  cfg.URL,
			Auth: auth,
		}); err != nil {
			if !errors.Is(err, transport.ErrEmptyRemoteRepository) {
				_ = fl.Unlock()
				return nil, fmt.Errorf("kauket: clone: %w", err)
			}
			if err := initEmptyRepo(cfg.RepoPath, cfg.URL); err != nil {
				_ = fl.Unlock()
				return nil, err
			}
		}
	}

	return &Store{
		repoPath: cfg.RepoPath,
		url:      cfg.URL,
		lockPath: cfg.LockPath,
		auth:     auth,
		lock:     fl,
		now:      now,
	}, nil
}

func initEmptyRepo(repoPath, url string) error {
	repo, err := gogit.PlainInit(repoPath, false)
	if err != nil {
		return fmt.Errorf("kauket: init repo: %w", err)
	}
	head := plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.NewBranchReferenceName(defaultBranch))
	if err := repo.Storer.SetReference(head); err != nil {
		return fmt.Errorf("kauket: set HEAD: %w", err)
	}
	if _, err := repo.CreateRemote(&config.RemoteConfig{
		Name: remoteName,
		URLs: []string{url},
	}); err != nil {
		return fmt.Errorf("kauket: create remote: %w", err)
	}
	return nil
}

func (s *Store) repo() (*gogit.Repository, error) {
	r, err := gogit.PlainOpen(s.repoPath)
	if err != nil {
		return nil, fmt.Errorf("kauket: open repo: %w", err)
	}
	return r, nil
}

func (s *Store) Sync(ctx context.Context) error {
	repo, err := s.repo()
	if err != nil {
		return err
	}
	err = repo.FetchContext(ctx, &gogit.FetchOptions{
		RemoteName: remoteName,
		RefSpecs:   []config.RefSpec{config.RefSpec(mainFetchRefSpec)},
		Auth:       s.auth,
	})
	if err != nil && !errors.Is(err, gogit.NoErrAlreadyUpToDate) && !errors.Is(err, transport.ErrEmptyRemoteRepository) {
		return fmt.Errorf("kauket: fetch: %w", err)
	}

	remoteRef, err := repo.Reference(plumbing.NewRemoteReferenceName(remoteName, defaultBranch), true)
	if err != nil {
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return nil
		}
		return fmt.Errorf("kauket: resolve remote ref: %w", err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("kauket: worktree: %w", err)
	}
	if err := wt.Reset(&gogit.ResetOptions{
		Commit: remoteRef.Hash(),
		Mode:   gogit.HardReset,
	}); err != nil {
		return fmt.Errorf("kauket: reset to remote: %w", err)
	}
	localRef := plumbing.NewHashReference(plumbing.NewBranchReferenceName(defaultBranch), remoteRef.Hash())
	if err := repo.Storer.SetReference(localRef); err != nil {
		return fmt.Errorf("kauket: update local main ref: %w", err)
	}
	return nil
}

func (s *Store) CommitAndPush(ctx context.Context, message string, author Author) error {
	repo, err := s.repo()
	if err != nil {
		return err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("kauket: worktree: %w", err)
	}
	if err := wt.AddWithOptions(&gogit.AddOptions{All: true}); err != nil {
		return fmt.Errorf("kauket: stage: %w", err)
	}
	status, err := wt.Status()
	if err != nil {
		return fmt.Errorf("kauket: status: %w", err)
	}
	if status.IsClean() {
		return nil
	}

	sig := &object.Signature{
		Name:  author.Name,
		Email: author.Email,
		When:  s.now(),
	}
	if _, err := wt.Commit(message, &gogit.CommitOptions{
		Author:    sig,
		Committer: sig,
	}); err != nil {
		return fmt.Errorf("kauket: commit: %w", err)
	}

	pushErr := repo.PushContext(ctx, &gogit.PushOptions{
		RemoteName: remoteName,
		RefSpecs:   []config.RefSpec{config.RefSpec("refs/heads/main:refs/heads/main")},
		Auth:       s.auth,
	})
	if pushErr == nil || errors.Is(pushErr, gogit.NoErrAlreadyUpToDate) {
		return nil
	}
	if isNonFastForward(pushErr) {
		if syncErr := s.Sync(ctx); syncErr != nil {
			return fmt.Errorf("kauket: sync after non-fast-forward: %w", syncErr)
		}
		return ErrNonFastForward
	}
	return fmt.Errorf("kauket: push: %w", pushErr)
}

func isNonFastForward(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "non-fast-forward") ||
		strings.Contains(msg, "non fast-forward") ||
		strings.Contains(msg, "fetch first") ||
		errors.Is(err, gogit.ErrNonFastForwardUpdate)
}
