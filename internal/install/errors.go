package install

import (
	"errors"
	"fmt"
)

var (
	ErrRelativeDest         = errors.New("destination must be absolute after expansion")
	ErrPathTraversal        = errors.New("destination contains path traversal segments")
	ErrUnmanagedDestination = errors.New("destination exists and was not installed by kauket")
	ErrParentNotDir         = errors.New("parent path is not a directory")
)

type SymlinkInPathError struct {
	Path string
}

func (e *SymlinkInPathError) Error() string {
	return fmt.Sprintf("refusing to write through symlink at %s", e.Path)
}

func (e *SymlinkInPathError) Is(target error) bool {
	_, ok := target.(*SymlinkInPathError)
	if ok {
		return true
	}
	return target == ErrSymlinkInPath
}

var ErrSymlinkInPath = &SymlinkInPathError{}
