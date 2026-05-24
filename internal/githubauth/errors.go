package githubauth

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	ErrGHNotInstalled     = errors.New("kauket: gh is not installed")
	ErrGHNotAuthenticated = errors.New("kauket: gh is not authenticated to github.com")
)

type InsufficientScopesError struct {
	Missing []string
}

func (e *InsufficientScopesError) Error() string {
	m := append([]string{}, e.Missing...)
	sort.Strings(m)
	return fmt.Sprintf("kauket: gh is authenticated but missing scopes [%s]", strings.Join(m, ", "))
}

func (e *InsufficientScopesError) Is(target error) bool {
	if target == ErrInsufficientScopes {
		return true
	}
	_, ok := target.(*InsufficientScopesError)
	return ok
}

var ErrInsufficientScopes = &InsufficientScopesError{}
