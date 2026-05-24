package gitstore

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-github/v67/github"
)

type DeployKeyManager struct {
	Owner      string
	Repo       string
	Token      string
	HTTPClient *http.Client
	BaseURL    string
}

type DeployKey struct {
	ID        int64
	Title     string
	Key       string
	ReadOnly  bool
	CreatedAt time.Time
}

var (
	hostIDPattern        = regexp.MustCompile(`^h_[a-z2-7]{16}$`)
	publicKeyPrefix      = "ssh-ed25519 AAAA"
	deployKeyTitlePrefix = "kauket "
)

func (m *DeployKeyManager) client() (*github.Client, error) {
	httpClient := m.HTTPClient
	c := github.NewClient(httpClient).WithAuthToken(m.Token)
	if m.BaseURL != "" {
		base, err := url.Parse(m.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("kauket: invalid deploy-key base url: %w", err)
		}
		c.BaseURL = base
	}
	return c, nil
}

func (m *DeployKeyManager) Add(ctx context.Context, hostID, publicKey string) (*DeployKey, error) {
	if !hostIDPattern.MatchString(hostID) {
		return nil, ErrInvalidHostID
	}
	trimmed := strings.TrimRight(publicKey, " \t\r\n")
	if !strings.HasPrefix(trimmed, publicKeyPrefix) {
		return nil, ErrInvalidPublicKey
	}
	title := deployKeyTitlePrefix + hostID
	in := &github.Key{
		Title:    github.String(title),
		Key:      github.String(trimmed),
		ReadOnly: github.Bool(true),
	}
	c, err := m.client()
	if err != nil {
		return nil, err
	}
	out, _, err := c.Repositories.CreateKey(ctx, m.Owner, m.Repo, in)
	if err != nil {
		return nil, fmt.Errorf("kauket: failed to add deploy key: %w", redactToken(err, m.Token))
	}
	return keyToDeployKey(out), nil
}

func (m *DeployKeyManager) List(ctx context.Context) ([]*DeployKey, error) {
	c, err := m.client()
	if err != nil {
		return nil, err
	}
	keys, _, err := c.Repositories.ListKeys(ctx, m.Owner, m.Repo, nil)
	if err != nil {
		return nil, fmt.Errorf("kauket: failed to list deploy keys: %w", redactToken(err, m.Token))
	}
	out := make([]*DeployKey, 0, len(keys))
	for _, k := range keys {
		out = append(out, keyToDeployKey(k))
	}
	return out, nil
}

func (m *DeployKeyManager) Delete(ctx context.Context, keyID int64) error {
	c, err := m.client()
	if err != nil {
		return err
	}
	_, err = c.Repositories.DeleteKey(ctx, m.Owner, m.Repo, keyID)
	if err != nil {
		return fmt.Errorf("kauket: failed to delete deploy key: %w", redactToken(err, m.Token))
	}
	return nil
}

func keyToDeployKey(k *github.Key) *DeployKey {
	if k == nil {
		return nil
	}
	dk := &DeployKey{
		ID:       k.GetID(),
		Title:    k.GetTitle(),
		Key:      k.GetKey(),
		ReadOnly: k.GetReadOnly(),
	}
	if t := k.GetCreatedAt(); !t.Time.IsZero() {
		dk.CreatedAt = t.Time
	}
	return dk
}

func redactToken(err error, token string) error {
	if err == nil || token == "" {
		return err
	}
	msg := err.Error()
	if !strings.Contains(msg, token) {
		return err
	}
	return fmt.Errorf("%s", strings.ReplaceAll(msg, token, "[redacted]"))
}
