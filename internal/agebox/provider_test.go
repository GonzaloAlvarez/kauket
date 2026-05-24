package agebox

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func TestFileIdentityProvider(t *testing.T) {
	t.Run("valid identity round trip", func(t *testing.T) {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatalf("generate identity: %v", err)
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "id.txt")
		if err := os.WriteFile(path, []byte(id.String()+"\n"), 0o600); err != nil {
			t.Fatalf("write identity: %v", err)
		}
		p := FileIdentityProvider{Path: path}
		ids, err := p.Identities()
		if err != nil {
			t.Fatalf("identities: %v", err)
		}
		if len(ids) != 1 {
			t.Fatalf("got %d identities, want 1", len(ids))
		}
		parsed, ok := ids[0].(*age.X25519Identity)
		if !ok {
			t.Fatalf("identity is not X25519Identity")
		}
		if parsed.Recipient().String() != id.Recipient().String() {
			t.Fatalf("recipient mismatch")
		}
	})

	t.Run("ignores comments and blanks", func(t *testing.T) {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatalf("generate identity: %v", err)
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "id.txt")
		body := "# this is a comment\n\n" + id.String() + "\n# trailing\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write identity: %v", err)
		}
		ids, err := FileIdentityProvider{Path: path}.Identities()
		if err != nil {
			t.Fatalf("identities: %v", err)
		}
		if len(ids) != 1 {
			t.Fatalf("got %d identities, want 1", len(ids))
		}
	})

	t.Run("nonexistent path returns error", func(t *testing.T) {
		p := FileIdentityProvider{Path: filepath.Join(t.TempDir(), "does-not-exist")}
		_, err := p.Identities()
		if err == nil {
			t.Fatalf("expected error for missing file")
		}
	})

	t.Run("garbage file returns parse error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "garbage.txt")
		if err := os.WriteFile(path, []byte("not an age identity\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, err := FileIdentityProvider{Path: path}.Identities()
		if err == nil {
			t.Fatalf("expected parse error")
		}
	})
}

func TestX25519RecipientProvider(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	good := id.Recipient().String()

	t.Run("single valid recipient", func(t *testing.T) {
		rs, err := X25519RecipientProvider{Strings: []string{good}}.Recipients()
		if err != nil {
			t.Fatalf("recipients: %v", err)
		}
		if len(rs) != 1 {
			t.Fatalf("got %d recipients, want 1", len(rs))
		}
	})

	t.Run("invalid recipient returns error", func(t *testing.T) {
		_, err := X25519RecipientProvider{Strings: []string{"not-a-recipient"}}.Recipients()
		if err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("one valid one invalid returns error", func(t *testing.T) {
		_, err := X25519RecipientProvider{Strings: []string{good, "garbage"}}.Recipients()
		if err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("empty input returns ErrNoRecipients", func(t *testing.T) {
		_, err := X25519RecipientProvider{Strings: []string{}}.Recipients()
		if !errors.Is(err, ErrNoRecipients) {
			t.Fatalf("expected ErrNoRecipients, got %v", err)
		}
	})

	t.Run("nil input returns ErrNoRecipients", func(t *testing.T) {
		_, err := X25519RecipientProvider{}.Recipients()
		if !errors.Is(err, ErrNoRecipients) {
			t.Fatalf("expected ErrNoRecipients, got %v", err)
		}
	})
}
