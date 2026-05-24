package bundle

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/gonzaloalvarez/kauket/internal/agebox"
	"github.com/gonzaloalvarez/kauket/internal/model"
)

func buildBundleVault(t *testing.T) (model.Vault, *age.X25519Identity, *age.X25519Identity, *age.X25519Identity, string) {
	t.Helper()
	admin1 := generateIdentity(t)
	admin2 := generateIdentity(t)
	hostID := "h_7j4v6m2q9xk3p8da"
	hostIdentity := generateIdentity(t)
	v := model.Vault{
		Schema:    1,
		StoreID:   "ks_6me7bk1f9s4xz2qa",
		CreatedAt: "2026-05-24T00:00:00Z",
		UpdatedAt: "2026-05-24T00:00:00Z",
		Admins: []model.AdminRecipient{
			{ID: "ar_aaaaaaaaaaaaaaaa", Recipient: admin1.Recipient().String(), CreatedAt: "2026-05-24T00:00:00Z"},
			{ID: "ar_bbbbbbbbbbbbbbbb", Recipient: admin2.Recipient().String(), CreatedAt: "2026-05-24T00:00:00Z"},
		},
		Profiles: map[string]model.Profile{
			"ssh":  {Description: "ssh"},
			"aws":  {Description: "aws"},
			"kube": {Description: "kube"},
		},
		Secrets: map[string]model.Secret{
			"ssh.main_private_key": {
				SecretObjectID: "s_aaaaaaaaaaaaaaaa",
				Kind:           "file",
				Profiles:       []string{"ssh"},
				Install:        model.InstallSpec{Destination: "~/.ssh/main_private_key", Mode: "0600", DirectoryMode: "0700"},
				ContentBase64:  "QUFBQQ==",
				SHA256:         "deadbeef",
				CreatedAt:      "2026-05-24T00:00:00Z",
				UpdatedAt:      "2026-05-24T00:00:00Z",
			},
			"aws.primary_account.key_file": {
				SecretObjectID: "s_bbbbbbbbbbbbbbbb",
				Kind:           "file",
				Profiles:       []string{"aws"},
				Install:        model.InstallSpec{Destination: "~/.aws/credentials", Mode: "0600", DirectoryMode: "0700"},
				ContentBase64:  "QkJCQg==",
				SHA256:         "cafebabe",
				CreatedAt:      "2026-05-24T00:00:00Z",
				UpdatedAt:      "2026-05-24T00:00:00Z",
			},
			"kube.cluster_config": {
				SecretObjectID: "s_cccccccccccccccc",
				Kind:           "file",
				Profiles:       []string{"kube"},
				Install:        model.InstallSpec{Destination: "~/.kube/config", Mode: "0600", DirectoryMode: "0700"},
				ContentBase64:  "Q0NDQw==",
				SHA256:         "feedface",
				CreatedAt:      "2026-05-24T00:00:00Z",
				UpdatedAt:      "2026-05-24T00:00:00Z",
			},
			"random.explicit_token": {
				SecretObjectID: "s_dddddddddddddddd",
				Kind:           "file",
				Profiles:       []string{"random"},
				Install:        model.InstallSpec{Destination: "~/.random/token", Mode: "0600", DirectoryMode: "0700"},
				ContentBase64:  "RERERA==",
				SHA256:         "babe1234",
				CreatedAt:      "2026-05-24T00:00:00Z",
				UpdatedAt:      "2026-05-24T00:00:00Z",
			},
		},
		Hosts: map[string]model.Host{
			hostID: {
				DisplayName:          "machine2",
				ReportedHostname:     "r730xd-debian",
				AgeRecipient:         hostIdentity.Recipient().String(),
				DeployKeyFingerprint: "SHA256:host",
				GrantedProfiles:      []string{"ssh"},
				GrantedSecrets:       []string{"random.explicit_token"},
				CreatedAt:            "2026-05-24T00:00:00Z",
				ApprovedAt:           "2026-05-24T00:00:00Z",
			},
		},
		Requests: map[string]model.RequestRecord{},
	}
	return v, admin1, admin2, hostIdentity, hostID
}

func TestBuildHostBundleSelectsGrantedSecrets(t *testing.T) {
	v, _, _, _, hostID := buildBundleVault(t)
	b, err := BuildHostBundle(v, hostID, time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC), 4)
	if err != nil {
		t.Fatalf("BuildHostBundle: %v", err)
	}
	if b.Schema != 1 {
		t.Fatalf("schema: got %d, want 1", b.Schema)
	}
	if b.StoreID != v.StoreID {
		t.Fatalf("StoreID: got %q, want %q", b.StoreID, v.StoreID)
	}
	if b.HostID != hostID {
		t.Fatalf("HostID: got %q, want %q", b.HostID, hostID)
	}
	if b.BundleGeneration != 4 {
		t.Fatalf("BundleGeneration: got %d, want 4", b.BundleGeneration)
	}
	if b.GeneratedAt != "2026-05-24T00:00:00Z" {
		t.Fatalf("GeneratedAt: got %q, want 2026-05-24T00:00:00Z", b.GeneratedAt)
	}

	wantKeys := map[string]bool{
		"ssh.main_private_key":  true,
		"random.explicit_token": true,
	}
	if len(b.Secrets) != len(wantKeys) {
		t.Fatalf("bundle has %d secrets, want %d", len(b.Secrets), len(wantKeys))
	}
	for k := range wantKeys {
		bs, ok := b.Secrets[k]
		if !ok {
			t.Fatalf("missing granted key %q", k)
		}
		if bs.ContentBase64 == "" {
			t.Fatalf("granted %q has empty content", k)
		}
		if bs.Kind != "file" {
			t.Fatalf("granted %q kind: got %q, want file", k, bs.Kind)
		}
		if bs.Install.Destination == "" {
			t.Fatalf("granted %q install destination missing", k)
		}
	}
	for _, ungranted := range []string{"aws.primary_account.key_file", "kube.cluster_config"} {
		if _, ok := b.Secrets[ungranted]; ok {
			t.Fatalf("ungranted secret %q included in bundle", ungranted)
		}
	}
}

func TestBuildHostBundleUnknownHostReturnsSentinel(t *testing.T) {
	v, _, _, _, _ := buildBundleVault(t)
	_, err := BuildHostBundle(v, "h_unknown", time.Now(), 1)
	if err == nil {
		t.Fatalf("expected error for unknown host")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("unknown host")) {
		t.Fatalf("expected unknown host error, got %v", err)
	}
}

func TestBundlePlaintextDoesNotIncludeHostMetadata(t *testing.T) {
	v, _, _, _, hostID := buildBundleVault(t)
	b, err := BuildHostBundle(v, hostID, time.Now(), 1)
	if err != nil {
		t.Fatalf("BuildHostBundle: %v", err)
	}
	pt, err := model.MarshalCanonical(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	lower := bytes.ToLower(pt)
	forbidden := []string{
		"display_name",
		"reported_hostname",
		"deploy_key_fingerprint",
		"machine2",
		"r730xd",
		"r730xd-debian",
	}
	for _, f := range forbidden {
		if bytes.Contains(lower, []byte(f)) {
			t.Fatalf("bundle plaintext contains forbidden token %q: %s", f, pt)
		}
	}
	if !bytes.Contains(lower, []byte("host_id")) {
		t.Fatalf("bundle plaintext missing host_id field")
	}
}

func TestEncodeDecodeHostBundleRoundTrip(t *testing.T) {
	v, admin1, admin2, hostIdentity, hostID := buildBundleVault(t)
	b, err := BuildHostBundle(v, hostID, time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC), 1)
	if err != nil {
		t.Fatalf("BuildHostBundle: %v", err)
	}
	hostRecip := agebox.X25519RecipientProvider{Strings: []string{hostIdentity.Recipient().String()}}
	adminRecips := agebox.X25519RecipientProvider{
		Strings: []string{admin1.Recipient().String(), admin2.Recipient().String()},
	}
	ct, err := EncodeHostBundle(b, hostRecip, adminRecips)
	if err != nil {
		t.Fatalf("EncodeHostBundle: %v", err)
	}

	want, err := model.MarshalCanonical(b)
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	identities := map[string]*age.X25519Identity{
		"host":   hostIdentity,
		"admin1": admin1,
		"admin2": admin2,
	}
	for name, id := range identities {
		ip := agebox.FileIdentityProvider{Path: writeIdentityFile(t, name+".txt", id)}
		decoded, err := DecodeHostBundle(ct, ip)
		if err != nil {
			t.Fatalf("%s decode: %v", name, err)
		}
		got, err := model.MarshalCanonical(decoded)
		if err != nil {
			t.Fatalf("%s marshal decoded: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s round trip mismatch", name)
		}
	}

	stranger := generateIdentity(t)
	ip := agebox.FileIdentityProvider{Path: writeIdentityFile(t, "stranger.txt", stranger)}
	if _, err := DecodeHostBundle(ct, ip); err == nil {
		t.Fatalf("expected unrelated identity to fail decryption")
	}
}

func TestAdminRecoveryAnyAdminDecryptsHostBundle(t *testing.T) {
	v, admin1, admin2, hostIdentity, hostID := buildBundleVault(t)
	b, err := BuildHostBundle(v, hostID, time.Now().UTC(), 7)
	if err != nil {
		t.Fatalf("BuildHostBundle: %v", err)
	}
	hostRecip := agebox.X25519RecipientProvider{Strings: []string{hostIdentity.Recipient().String()}}
	adminRecips := agebox.X25519RecipientProvider{
		Strings: []string{admin1.Recipient().String(), admin2.Recipient().String()},
	}
	ct, err := EncodeHostBundle(b, hostRecip, adminRecips)
	if err != nil {
		t.Fatalf("EncodeHostBundle: %v", err)
	}
	for name, id := range map[string]*age.X25519Identity{"admin1": admin1, "admin2": admin2} {
		ip := agebox.FileIdentityProvider{Path: writeIdentityFile(t, name+".txt", id)}
		if _, err := DecodeHostBundle(ct, ip); err != nil {
			t.Fatalf("admin recovery via %s failed: %v", name, err)
		}
	}
}

func TestHostBundleCiphertextDoesNotLeakSecretNamesOrContent(t *testing.T) {
	_, admin1, _, hostIdentity, hostID := buildBundleVault(t)
	openSSHHeader := "-----BEGIN OPENSSH PRIVATE KEY-----\nfakebodyfakebodyfakebodyfakebody\n-----END OPENSSH PRIVATE KEY-----"
	v := model.Vault{
		Schema:    1,
		StoreID:   "ks_6me7bk1f9s4xz2qa",
		CreatedAt: "2026-05-24T00:00:00Z",
		UpdatedAt: "2026-05-24T00:00:00Z",
		Admins: []model.AdminRecipient{
			{ID: "ar_aaaaaaaaaaaaaaaa", Recipient: admin1.Recipient().String(), CreatedAt: "2026-05-24T00:00:00Z"},
		},
		Profiles: map[string]model.Profile{"ssh": {Description: "ssh"}},
		Secrets: map[string]model.Secret{
			"ssh.main_private_key": {
				SecretObjectID: "s_aaaaaaaaaaaaaaaa",
				Kind:           "file",
				Profiles:       []string{"ssh"},
				Install:        model.InstallSpec{Destination: "~/.ssh/main_private_key", Mode: "0600", DirectoryMode: "0700"},
				ContentBase64:  base64.StdEncoding.EncodeToString([]byte(openSSHHeader)),
				SHA256:         "deadbeef",
				CreatedAt:      "2026-05-24T00:00:00Z",
				UpdatedAt:      "2026-05-24T00:00:00Z",
			},
		},
		Hosts: map[string]model.Host{
			hostID: {
				DisplayName:          "machine2",
				ReportedHostname:     "r730xd-debian",
				AgeRecipient:         hostIdentity.Recipient().String(),
				DeployKeyFingerprint: "SHA256:host",
				GrantedProfiles:      []string{"ssh"},
				GrantedSecrets:       []string{},
				CreatedAt:            "2026-05-24T00:00:00Z",
				ApprovedAt:           "2026-05-24T00:00:00Z",
			},
		},
		Requests: map[string]model.RequestRecord{},
	}
	b, err := BuildHostBundle(v, hostID, time.Now().UTC(), 1)
	if err != nil {
		t.Fatalf("BuildHostBundle: %v", err)
	}
	hostRecip := agebox.X25519RecipientProvider{Strings: []string{hostIdentity.Recipient().String()}}
	adminRecips := agebox.X25519RecipientProvider{Strings: []string{admin1.Recipient().String()}}
	ct, err := EncodeHostBundle(b, hostRecip, adminRecips)
	if err != nil {
		t.Fatalf("EncodeHostBundle: %v", err)
	}
	lower := bytes.ToLower(ct)
	disallowed := []string{
		"ssh.main_private_key",
		"main_private_key",
		"begin openssh",
		"r730xd",
		"machine2",
	}
	for _, d := range disallowed {
		if bytes.Contains(lower, []byte(d)) {
			t.Fatalf("ciphertext leaks %q", d)
		}
	}
	if len(ct) < 16*1024 {
		t.Fatalf("ciphertext length %d is smaller than 16 KiB padding floor", len(ct))
	}
}

func TestHostBundlePaddingClassConsistent(t *testing.T) {
	v, admin1, _, hostIdentity, hostID := buildBundleVault(t)
	hostRecip := agebox.X25519RecipientProvider{Strings: []string{hostIdentity.Recipient().String()}}
	adminRecips := agebox.X25519RecipientProvider{Strings: []string{admin1.Recipient().String()}}

	bA, err := BuildHostBundle(v, hostID, time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC), 1)
	if err != nil {
		t.Fatalf("BuildHostBundle A: %v", err)
	}
	ctA, err := EncodeHostBundle(bA, hostRecip, adminRecips)
	if err != nil {
		t.Fatalf("EncodeHostBundle A: %v", err)
	}

	bB := bA
	bB.BundleGeneration = 2
	ctB, err := EncodeHostBundle(bB, hostRecip, adminRecips)
	if err != nil {
		t.Fatalf("EncodeHostBundle B: %v", err)
	}
	if len(ctA) < 16*1024 || len(ctB) < 16*1024 {
		t.Fatalf("padded ciphertexts unexpectedly small: A=%d B=%d", len(ctA), len(ctB))
	}
	if len(ctA) != len(ctB) {
		t.Fatalf("expected identical lengths for same-class bundles: A=%d B=%d", len(ctA), len(ctB))
	}
}
