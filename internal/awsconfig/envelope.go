package awsconfig

import (
	"encoding/json"
	"fmt"
)

const EnvelopeSchema = 1

type Envelope struct {
	Schema      int    `json:"schema"`
	Profile     string `json:"profile"`
	Config      string `json:"config"`
	Credentials string `json:"credentials"`
}

func ParseEnvelope(data []byte) (Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return Envelope{}, fmt.Errorf("malformed aws profile envelope: %w", err)
	}
	if e.Schema != EnvelopeSchema {
		return Envelope{}, fmt.Errorf("unsupported aws profile envelope schema %d; upgrade kauket", e.Schema)
	}
	if e.Profile == "" {
		return Envelope{}, fmt.Errorf("aws profile envelope missing profile name")
	}
	if e.Config == "" && e.Credentials == "" {
		return Envelope{}, fmt.Errorf("aws profile envelope has no config or credentials content")
	}
	return e, nil
}

func (e Envelope) Marshal() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}
