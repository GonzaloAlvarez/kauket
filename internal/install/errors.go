package install

import (
	"errors"
	"fmt"
)

var (
	ErrRelativeDest           = errors.New("destination must be absolute after expansion")
	ErrPathTraversal          = errors.New("destination contains path traversal segments")
	ErrUnmanagedDestination   = errors.New("destination exists and was not installed by kauket")
	ErrUnmanagedSection       = errors.New("existing aws profile section was not installed by kauket")
	ErrParentNotDir           = errors.New("parent path is not a directory")
	ErrDestinationOutsideRoot = errors.New("destination is outside the allowed install root")
	ErrDeniedTarget           = errors.New("destination targets a sensitive path kauket refuses to write")
	ErrUnsafeMode             = errors.New("refusing an install mode that would expose or execute a secret")
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
