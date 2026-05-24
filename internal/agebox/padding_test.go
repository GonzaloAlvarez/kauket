package agebox

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestWrapSizeClasses(t *testing.T) {
	cases := []struct {
		name      string
		payload   int
		wantClass int
	}{
		{"empty fits 16K", 0, 16 * 1024},
		{"one byte fits 16K", 1, 16 * 1024},
		{"near 16K boundary fits 16K", 16*1024/4*3 - 100, 16 * 1024},
		{"just over 16K capacity rolls to 64K", 16 * 1024, 64 * 1024},
		{"mid 64K stays in 64K", 32 * 1024, 64 * 1024},
		{"just over 64K capacity rolls to 256K", 64 * 1024, 256 * 1024},
		{"mid 256K stays in 256K", 128 * 1024, 256 * 1024},
		{"just over 256K capacity rolls to 1M", 256 * 1024, 1024 * 1024},
		{"mid 1M stays in 1M", 512 * 1024, 1024 * 1024},
		{"just over 1M capacity rolls to 4M", 1024 * 1024, 4 * 1024 * 1024},
		{"mid 4M stays in 4M", 2 * 1024 * 1024, 4 * 1024 * 1024},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			payload := make([]byte, c.payload)
			if _, err := rand.Read(payload); err != nil {
				t.Fatalf("rand: %v", err)
			}
			wrapped, err := Wrap(payload, 0)
			if err != nil {
				t.Fatalf("wrap: %v", err)
			}
			if len(wrapped) != c.wantClass {
				t.Fatalf("wrapped len = %d, want %d", len(wrapped), c.wantClass)
			}
			got, err := Unwrap(wrapped)
			if err != nil {
				t.Fatalf("unwrap: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("round trip mismatch")
			}
		})
	}
}

func TestWrapLargestPerClass(t *testing.T) {
	classes := []int{16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024}
	for _, c := range classes {
		t.Run("class", func(t *testing.T) {
			low := 0
			high := c
			largest := -1
			for low <= high {
				mid := (low + high) / 2
				payload := make([]byte, mid)
				wrapped, err := Wrap(payload, 0)
				if err != nil {
					high = mid - 1
					continue
				}
				if len(wrapped) == c {
					largest = mid
					low = mid + 1
				} else if len(wrapped) < c {
					low = mid + 1
				} else {
					high = mid - 1
				}
			}
			if largest < 0 {
				t.Fatalf("could not find largest payload for class %d", c)
			}
			t.Logf("class %d largest payload = %d bytes", c, largest)
		})
	}
}

func TestWrapTooLarge(t *testing.T) {
	payload := make([]byte, 4*1024*1024+1)
	_, err := Wrap(payload, 0)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
}

func TestWrapWithCustomCap(t *testing.T) {
	payload := make([]byte, 4*1024*1024+1)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	wrapped, err := Wrap(payload, 8*1024*1024)
	if err != nil {
		t.Fatalf("wrap with cap 8MiB: %v", err)
	}
	if len(wrapped) > 8*1024*1024 {
		t.Fatalf("wrapped size %d exceeds 8 MiB cap", len(wrapped))
	}
	got, err := Unwrap(wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round trip mismatch")
	}
}

func TestWrapRoundTripRandom(t *testing.T) {
	sizes := []int{1, 1 * 1024, 100 * 1024, 1 * 1024 * 1024}
	for _, n := range sizes {
		t.Run("size", func(t *testing.T) {
			payload := make([]byte, n)
			if _, err := rand.Read(payload); err != nil {
				t.Fatalf("rand: %v", err)
			}
			wrapped, err := Wrap(payload, 0)
			if err != nil {
				t.Fatalf("wrap %d: %v", n, err)
			}
			got, err := Unwrap(wrapped)
			if err != nil {
				t.Fatalf("unwrap %d: %v", n, err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("mismatch at size %d", n)
			}
		})
	}
}

func TestWrapPaddingIsRandom(t *testing.T) {
	payload := []byte("kauket determinism check")
	a, err := Wrap(payload, 0)
	if err != nil {
		t.Fatalf("wrap a: %v", err)
	}
	b, err := Wrap(payload, 0)
	if err != nil {
		t.Fatalf("wrap b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("expected different wrapped outputs from random padding")
	}
	pa, err := Unwrap(a)
	if err != nil {
		t.Fatalf("unwrap a: %v", err)
	}
	pb, err := Unwrap(b)
	if err != nil {
		t.Fatalf("unwrap b: %v", err)
	}
	if !bytes.Equal(pa, payload) || !bytes.Equal(pb, payload) {
		t.Fatalf("payload mismatch after unwrap")
	}
}

func TestWrapBoundaryExactFit(t *testing.T) {
	for _, c := range []int{16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024} {
		n := 0
		for {
			payload := make([]byte, n)
			wrapped, err := Wrap(payload, 0)
			if err != nil {
				break
			}
			if len(wrapped) != c {
				if n > 0 {
					prev := make([]byte, n-1)
					prevWrapped, prevErr := Wrap(prev, 0)
					if prevErr != nil || len(prevWrapped) != c {
						t.Fatalf("class %d: expected exact-fit boundary at n=%d to wrap to %d, got %d", c, n-1, c, len(prevWrapped))
					}
				}
				break
			}
			n++
			if n > c {
				t.Fatalf("class %d: did not roll over", c)
			}
		}
	}
}
