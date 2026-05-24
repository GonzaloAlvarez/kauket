package gitstore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

const (
	lockAttempts = 10
	lockBackoff  = 100 * time.Millisecond
)

func acquireLock(ctx context.Context, lockPath string) (*flock.Flock, error) {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, fmt.Errorf("kauket: ensure lock dir: %w", err)
	}
	fl := flock.New(lockPath)
	for i := 0; i < lockAttempts; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ok, err := fl.TryLock()
		if err != nil {
			return nil, fmt.Errorf("kauket: trylock: %w", err)
		}
		if ok {
			return fl, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(lockBackoff):
		}
	}
	return nil, ErrLocked
}

func (s *Store) Close() error {
	if s == nil || s.lock == nil {
		return nil
	}
	if err := s.lock.Unlock(); err != nil {
		return fmt.Errorf("kauket: unlock: %w", err)
	}
	s.lock = nil
	return nil
}
