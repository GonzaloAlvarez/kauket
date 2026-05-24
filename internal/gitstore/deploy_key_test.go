package gitstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testOwner    = "GonzaloAlvarez"
	testRepo     = "kauket-store"
	testHostID   = "h_abcdefghjkmnpqrs"
	testPubKey   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH2P+H1xJh0Yt9wMqLZbvF9aQp1xN8GhRgVrK3y8q4j5 user@host"
	testFakeAuth = "FAKE_DEPLOY_KEY_TOKEN_xxxx"
)

type capturedKey struct {
	Title    *string `json:"title"`
	Key      *string `json:"key"`
	ReadOnly *bool   `json:"read_only"`
}

func stubServer(t *testing.T, handler http.HandlerFunc) (string, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	base := srv.URL + "/"
	return base, srv.Close
}

func decodeCreateKey(t *testing.T, r *http.Request) capturedKey {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var ck capturedKey
	if err := json.Unmarshal(body, &ck); err != nil {
		t.Fatalf("unmarshal body %q: %v", string(body), err)
	}
	return ck
}

func writeCreatedKey(t *testing.T, w http.ResponseWriter, id int64, title, key string, readOnly bool) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	resp := map[string]any{
		"id":         id,
		"title":      title,
		"key":        key,
		"read_only":  readOnly,
		"created_at": "2026-05-24T12:00:00Z",
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		t.Fatalf("encode resp: %v", err)
	}
}

func TestAddDeployKeyTitleIsOpaque(t *testing.T) {
	wantTitle := "kauket " + testHostID
	wantPath := fmt.Sprintf("/repos/%s/%s/keys", testOwner, testRepo)
	base, stop := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != wantPath {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		ck := decodeCreateKey(t, r)
		if ck.Title == nil || *ck.Title != wantTitle {
			t.Fatalf("title mismatch: want %q got %v", wantTitle, ck.Title)
		}
		if ck.ReadOnly == nil || !*ck.ReadOnly {
			t.Fatal("ReadOnly must be true")
		}
		writeCreatedKey(t, w, 7, *ck.Title, *ck.Key, *ck.ReadOnly)
	})
	defer stop()

	m := &DeployKeyManager{
		Owner:   testOwner,
		Repo:    testRepo,
		Token:   "ghs_test",
		BaseURL: base,
	}
	got, err := m.Add(context.Background(), testHostID, testPubKey)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if got.Title != wantTitle {
		t.Fatalf("title: want %q got %q", wantTitle, got.Title)
	}
	if got.ID != 7 {
		t.Fatalf("id: want 7 got %d", got.ID)
	}
	if !got.ReadOnly {
		t.Fatal("ReadOnly: want true got false")
	}
	if got.Key != testPubKey {
		t.Fatalf("key: want %q got %q", testPubKey, got.Key)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("CreatedAt: want non-zero")
	}
	for _, leak := range []string{"machine2", "r730xd", "hostname", "ssh"} {
		if strings.Contains(strings.ToLower(got.Title), leak) {
			t.Fatalf("title %q leaks word %q", got.Title, leak)
		}
	}
}

func TestAddDeployKeyReadOnlyMandatory(t *testing.T) {
	base, stop := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		ck := decodeCreateKey(t, r)
		if ck.ReadOnly == nil {
			t.Fatal("ReadOnly must be true")
		}
		if !*ck.ReadOnly {
			t.Fatal("ReadOnly must be true")
		}
		writeCreatedKey(t, w, 1, *ck.Title, *ck.Key, *ck.ReadOnly)
	})
	defer stop()

	m := &DeployKeyManager{
		Owner:   testOwner,
		Repo:    testRepo,
		Token:   "ghs_test",
		BaseURL: base,
	}
	if _, err := m.Add(context.Background(), testHostID, testPubKey); err != nil {
		t.Fatalf("Add: %v", err)
	}
}

func TestAddDeployKeyRejectsInvalidHostID(t *testing.T) {
	base, stop := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("server must not be called for invalid host id, got %s %s", r.Method, r.URL.Path)
	})
	defer stop()

	m := &DeployKeyManager{
		Owner:   testOwner,
		Repo:    testRepo,
		Token:   "ghs_test",
		BaseURL: base,
	}
	for _, bad := range []string{"machine2", "ssh.foo", "", "h_TOOSHORT", "h_ABCDEF1234567890", "host_abcdef1234567890"} {
		_, err := m.Add(context.Background(), bad, testPubKey)
		if !errors.Is(err, ErrInvalidHostID) {
			t.Fatalf("host id %q: want ErrInvalidHostID, got %v", bad, err)
		}
	}
}

func TestAddDeployKeyRejectsNonEd25519(t *testing.T) {
	base, stop := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("server must not be called for invalid key, got %s %s", r.Method, r.URL.Path)
	})
	defer stop()

	m := &DeployKeyManager{
		Owner:   testOwner,
		Repo:    testRepo,
		Token:   "ghs_test",
		BaseURL: base,
	}
	for _, bad := range []string{
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDexample user@host",
		"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAA",
		"",
		"not a key",
		"AAAA ssh-ed25519",
	} {
		_, err := m.Add(context.Background(), testHostID, bad)
		if !errors.Is(err, ErrInvalidPublicKey) {
			t.Fatalf("key %q: want ErrInvalidPublicKey, got %v", bad, err)
		}
	}
}

func TestAddDeployKeyDoesNotLeakToken(t *testing.T) {
	base, stop := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message":"Bad credentials","documentation_url":"https://docs.github.com/rest"}`)
	})
	defer stop()

	m := &DeployKeyManager{
		Owner:   testOwner,
		Repo:    testRepo,
		Token:   testFakeAuth,
		BaseURL: base,
	}
	_, err := m.Add(context.Background(), testHostID, testPubKey)
	if err == nil {
		t.Fatal("expected error on 401, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "deploy key") {
		t.Fatalf("error %q does not mention \"deploy key\"", msg)
	}
	if strings.Contains(msg, testFakeAuth) {
		t.Fatalf("error %q leaks token %q", msg, testFakeAuth)
	}
}

func TestListDeployKeys(t *testing.T) {
	wantPath := fmt.Sprintf("/repos/%s/%s/keys", testOwner, testRepo)
	base, stop := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != wantPath {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := []map[string]any{
			{
				"id":         int64(11),
				"title":      "kauket " + testHostID,
				"key":        testPubKey,
				"read_only":  true,
				"created_at": "2026-05-24T12:00:00Z",
			},
			{
				"id":         int64(12),
				"title":      "kauket h_qrstuvwxyz234567",
				"key":        "ssh-ed25519 AAAAOther example",
				"read_only":  true,
				"created_at": "2026-05-25T13:30:00Z",
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer stop()

	m := &DeployKeyManager{
		Owner:   testOwner,
		Repo:    testRepo,
		Token:   "ghs_test",
		BaseURL: base,
	}
	got, err := m.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 keys, got %d", len(got))
	}
	if got[0].ID != 11 || got[1].ID != 12 {
		t.Fatalf("ids: want [11 12], got [%d %d]", got[0].ID, got[1].ID)
	}
	if !got[0].ReadOnly || !got[1].ReadOnly {
		t.Fatalf("expected both ReadOnly true, got [%v %v]", got[0].ReadOnly, got[1].ReadOnly)
	}
	if got[0].Title != "kauket "+testHostID {
		t.Fatalf("title[0]: want %q got %q", "kauket "+testHostID, got[0].Title)
	}
	wantCreated := time.Date(2026, time.May, 24, 12, 0, 0, 0, time.UTC)
	if !got[0].CreatedAt.Equal(wantCreated) {
		t.Fatalf("CreatedAt[0]: want %v got %v", wantCreated, got[0].CreatedAt)
	}
}

func TestDeleteDeployKey(t *testing.T) {
	wantPath := fmt.Sprintf("/repos/%s/%s/keys/42", testOwner, testRepo)
	base, stop := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != wantPath {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer stop()

	m := &DeployKeyManager{
		Owner:   testOwner,
		Repo:    testRepo,
		Token:   "ghs_test",
		BaseURL: base,
	}
	if err := m.Delete(context.Background(), 42); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestDeleteDeployKeyNotFoundWrapsError(t *testing.T) {
	base, stop := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"Not Found","documentation_url":"https://docs.github.com/rest"}`)
	})
	defer stop()

	m := &DeployKeyManager{
		Owner:   testOwner,
		Repo:    testRepo,
		Token:   "ghs_test",
		BaseURL: base,
	}
	err := m.Delete(context.Background(), 99)
	if err == nil {
		t.Fatal("want error on 404, got nil")
	}
	if !strings.Contains(err.Error(), "deploy key") {
		t.Fatalf("error %q does not mention \"deploy key\"", err.Error())
	}
}

func TestAddDeployKeyTrimsTrailingWhitespace(t *testing.T) {
	wantKey := testPubKey
	base, stop := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		ck := decodeCreateKey(t, r)
		if ck.Key == nil || *ck.Key != wantKey {
			t.Fatalf("key not trimmed: want %q got %v", wantKey, ck.Key)
		}
		if ck.ReadOnly == nil || !*ck.ReadOnly {
			t.Fatal("ReadOnly must be true")
		}
		writeCreatedKey(t, w, 5, *ck.Title, *ck.Key, *ck.ReadOnly)
	})
	defer stop()

	m := &DeployKeyManager{
		Owner:   testOwner,
		Repo:    testRepo,
		Token:   "ghs_test",
		BaseURL: base,
	}
	if _, err := m.Add(context.Background(), testHostID, testPubKey+"\n\n\t "); err != nil {
		t.Fatalf("Add: %v", err)
	}
}
