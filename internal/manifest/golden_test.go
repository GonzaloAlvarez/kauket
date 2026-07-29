package manifest

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gonzaloalvarez/kauket/internal/model"
)

func goldenCases(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}

	manifestPayload, err := model.MarshalCanonical(fixtureBody())
	if err != nil {
		t.Fatalf("canonical manifest: %v", err)
	}
	out["manifest_signable_payload.json"] = manifestPayload

	indexPayload, err := model.MarshalCanonical(fixtureIndex())
	if err != nil {
		t.Fatalf("canonical index: %v", err)
	}
	out["index.json"] = indexPayload

	objectPayload, err := model.MarshalCanonical(fixtureObject())
	if err != nil {
		t.Fatalf("canonical object: %v", err)
	}
	out["object.json"] = objectPayload

	rootPayload, err := model.MarshalCanonical(fixtureStoreRoot())
	if err != nil {
		t.Fatalf("canonical store root: %v", err)
	}
	out["store_root_signable_payload.json"] = rootPayload

	routed := RoutedRequest{
		Schema:       Schema,
		Kind:         KindRoutedRequest,
		StoreID:      "ks_fixturestore1234",
		RequestID:    "rq_fixturereq123456",
		RoutedBy:     "i_fixtureowner12345",
		RoutedAt:     "2026-07-28T00:00:00Z",
		TargetNodeID: "n_fixturenode123456",
	}
	routedPayload, err := model.MarshalCanonical(routed)
	if err != nil {
		t.Fatalf("canonical routed request: %v", err)
	}
	out["routed_request.json"] = routedPayload

	v1Request := model.Request{
		Schema:    1,
		StoreID:   "ks_fixturestore1234",
		RequestID: "rq_fixturereq123456",
		CreatedAt: "2026-07-28T00:00:00Z",
		Host: model.RequestHost{
			ID:                 "h_fixturehost12345",
			DisplayName:        "machine2",
			ReportedHostname:   "machine2.local",
			OS:                 "linux",
			Arch:               "amd64",
			AgeRecipient:       "age1fixturehost",
			GitDeployPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureDeployKey0000000000000000000000",
		},
		Requested: model.RequestedItems{Profiles: []string{"ssh"}},
	}
	v1Payload, err := model.MarshalCanonical(v1Request)
	if err != nil {
		t.Fatalf("canonical v1 request: %v", err)
	}
	out["v1_request_signable_payload.json"] = v1Payload

	return out
}

func TestV1RequestCanonicalBytesHaveNoNewFields(t *testing.T) {
	for name, payload := range goldenCases(t) {
		if name != "v1_request_signable_payload.json" {
			continue
		}
		for _, forbidden := range []string{`"paths"`, `"kind"`} {
			if strings.Contains(string(payload), forbidden) {
				t.Fatalf("v1 request canonical bytes gained %s; old signatures would break", forbidden)
			}
		}
	}
}

func TestGoldenCanonicalBodies(t *testing.T) {
	dir := filepath.Join("testdata", "golden")
	update := os.Getenv("UPDATE_GOLDEN") == "1"
	for name, payload := range goldenCases(t) {
		path := filepath.Join(dir, name)
		if update {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("mkdir golden: %v", err)
			}
			if err := os.WriteFile(path, payload, 0o644); err != nil {
				t.Fatalf("write golden %s: %v", name, err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read golden %s (run UPDATE_GOLDEN=1 go test once to generate): %v", name, err)
		}
		if !bytes.Equal(payload, want) {
			t.Fatalf("canonical bytes for %s changed; this breaks existing signatures.\n got: %s\nwant: %s", name, payload, want)
		}
	}
}
