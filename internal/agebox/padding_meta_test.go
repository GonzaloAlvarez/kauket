package agebox

import (
	"bytes"
	"testing"
)

func TestWrapMetaSmallPayloadUses4K(t *testing.T) {
	payload := []byte("small manifest body")
	wrapped, err := WrapMeta(payload)
	if err != nil {
		t.Fatalf("WrapMeta: %v", err)
	}
	if len(wrapped) != 4*1024 {
		t.Fatalf("wrapped size = %d, want 4096", len(wrapped))
	}
	out, err := Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("round trip mismatch")
	}
}

func TestWrapMetaGrowsThroughClasses(t *testing.T) {
	cases := []struct {
		payloadLen int
		wantSize   int
	}{
		{100, 4 * 1024},
		{5 * 1024, 16 * 1024},
		{20 * 1024, 64 * 1024},
		{100 * 1024, 256 * 1024},
	}
	for _, tc := range cases {
		payload := bytes.Repeat([]byte("m"), tc.payloadLen)
		wrapped, err := WrapMeta(payload)
		if err != nil {
			t.Fatalf("WrapMeta(%d): %v", tc.payloadLen, err)
		}
		if len(wrapped) != tc.wantSize {
			t.Fatalf("payload %d: wrapped size = %d, want %d", tc.payloadLen, len(wrapped), tc.wantSize)
		}
		out, err := Unwrap(wrapped)
		if err != nil {
			t.Fatalf("Unwrap: %v", err)
		}
		if !bytes.Equal(out, payload) {
			t.Fatalf("round trip mismatch at %d", tc.payloadLen)
		}
	}
}

func TestWrapStillStartsAt16K(t *testing.T) {
	wrapped, err := Wrap([]byte("tiny v1 payload"), 0)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if len(wrapped) != 16*1024 {
		t.Fatalf("v1 Wrap minimum class changed: got %d, want 16384", len(wrapped))
	}
}
