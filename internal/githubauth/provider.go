package githubauth

import "context"

type Provider interface {
	Token(ctx context.Context, scopes []string) (string, error)
}
