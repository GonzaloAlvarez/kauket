package agebox

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

var ErrTooLarge = errors.New("payload exceeds maximum padded size")

const (
	classOverhead  = 41
	defaultMaxSize = 4 * 1024 * 1024
)

var paddingClasses = []int{
	16 * 1024,
	64 * 1024,
	256 * 1024,
	1024 * 1024,
	4 * 1024 * 1024,
}

type paddingEnvelope struct {
	PayloadBase64 string `json:"payload_base64"`
	PaddingBase64 string `json:"padding_base64"`
}

func Wrap(payload []byte, maxSize int) ([]byte, error) {
	payloadB64 := base64.StdEncoding.EncodeToString(payload)
	base := classOverhead + len(payloadB64)

	limit := defaultMaxSize
	if maxSize > 0 {
		limit = maxSize
	}

	classes := paddingClasses
	if limit > paddingClasses[len(paddingClasses)-1] {
		classes = append(append([]int(nil), paddingClasses...), limit)
	}

	target := -1
	for _, c := range classes {
		if c > limit {
			continue
		}
		if c-base >= 3 {
			target = c
			break
		}
	}
	if target < 0 {
		return nil, ErrTooLarge
	}

	needed := target - base
	rawN := (needed * 3) / 4
	raw := make([]byte, rawN)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("failed to read random padding: %w", err)
	}
	paddingB64 := base64.RawStdEncoding.EncodeToString(raw)
	if len(paddingB64) != needed {
		return nil, fmt.Errorf("internal padding length mismatch")
	}

	env := paddingEnvelope{
		PayloadBase64: payloadB64,
		PaddingBase64: paddingB64,
	}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal envelope: %w", err)
	}
	if len(out) != target {
		return nil, fmt.Errorf("internal envelope length mismatch: got %d want %d", len(out), target)
	}
	return out, nil
}

func Unwrap(wrapped []byte) ([]byte, error) {
	var env paddingEnvelope
	if err := json.Unmarshal(wrapped, &env); err != nil {
		return nil, fmt.Errorf("failed to parse envelope: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.PayloadBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}
	return payload, nil
}
