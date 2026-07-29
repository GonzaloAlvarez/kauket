package manifest

import "github.com/gonzaloalvarez/kauket/internal/model"

const (
	Schema            = 2
	KindManifest      = "manifest"
	KindIndex         = "index"
	KindRoutedRequest = "routed_request"

	FormatManifest      = "kauket-manifest-v2"
	FormatIndex         = "kauket-index-v2"
	FormatObject        = "kauket-object-v2"
	FormatRoutedRequest = "kauket-routed-request-v2"
)

type Signature = model.RequestSignature

type Member struct {
	IID          string `json:"i_id"`
	AgeRecipient string `json:"age_recipient"`
}

type Owner struct {
	IID          string `json:"i_id"`
	AgeRecipient string `json:"age_recipient"`
	SignPubkey   string `json:"sign_pubkey"`
}

type ChildAttestation struct {
	NodeID        string   `json:"node_id"`
	OwnerSignKeys []string `json:"owner_sign_keys"`
}

type ManifestBody struct {
	Schema             int                `json:"schema"`
	Kind               string             `json:"kind"`
	StoreID            string             `json:"store_id"`
	NodeID             string             `json:"node_id"`
	Version            int                `json:"version"`
	UpdatedAt          string             `json:"updated_at"`
	Name               string             `json:"name"`
	ParentID           string             `json:"parent_id"`
	Children           []ChildAttestation `json:"children"`
	Owners             []Owner            `json:"owners"`
	Readers            []Member           `json:"readers"`
	ExtraReaders       []Member           `json:"extra_readers"`
	IndexObjectID      string             `json:"index_object_id"`
	IndexSHA256        string             `json:"index_sha256"`
	PrevManifestSHA256 string             `json:"prev_manifest_sha256"`
	Signature          *Signature         `json:"signature,omitempty"`
}

type ManifestFile struct {
	Body       ManifestBody `json:"body"`
	Recipients []string     `json:"recipients"`
}

type IndexEntry struct {
	ObjectID     string   `json:"object_id"`
	ObjectSHA256 string   `json:"object_sha256"`
	Kind         string   `json:"kind"`
	Readers      []Member `json:"readers"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
}

type Index struct {
	Schema  int                   `json:"schema"`
	Kind    string                `json:"kind"`
	StoreID string                `json:"store_id"`
	NodeID  string                `json:"node_id"`
	Entries map[string]IndexEntry `json:"entries"`
}

type Object struct {
	Schema        int               `json:"schema"`
	Kind          string            `json:"kind"`
	StoreID       string            `json:"store_id"`
	ObjectID      string            `json:"object_id"`
	Install       model.InstallSpec `json:"install"`
	ContentBase64 string            `json:"content_base64"`
	SHA256        string            `json:"sha256"`
	CreatedAt     string            `json:"created_at"`
	UpdatedAt     string            `json:"updated_at"`
}

type RoutedRequest struct {
	Schema       int           `json:"schema"`
	Kind         string        `json:"kind"`
	StoreID      string        `json:"store_id"`
	RequestID    string        `json:"request_id"`
	RoutedBy     string        `json:"routed_by"`
	RoutedAt     string        `json:"routed_at"`
	TargetNodeID string        `json:"target_node_id"`
	Request      model.Request `json:"request"`
}

type StoreFormat struct {
	Manifest      string `json:"manifest"`
	Index         string `json:"index"`
	Object        string `json:"object"`
	RoutedRequest string `json:"routed_request"`
	Request       string `json:"request"`
	Encryption    string `json:"encryption"`
}

type StoreGitHub struct {
	Owner         string `json:"owner"`
	Repo          string `json:"repo"`
	DefaultBranch string `json:"default_branch"`
}

type TrustAnchor struct {
	IID          string `json:"i_id"`
	SignPubkey   string `json:"sign_pubkey"`
	AgeRecipient string `json:"age_recipient,omitempty"`
}

type RecoveryKey struct {
	AgeRecipient string `json:"age_recipient"`
	SignPubkey   string `json:"sign_pubkey"`
}

type StoreRoot struct {
	Schema       int           `json:"schema"`
	StoreID      string        `json:"store_id"`
	CreatedAt    string        `json:"created_at"`
	Format       StoreFormat   `json:"format"`
	GitHub       StoreGitHub   `json:"github"`
	RootNodeID   string        `json:"root_node_id"`
	TrustAnchors []TrustAnchor `json:"trust_anchors"`
	Recovery     []RecoveryKey `json:"recovery"`
	FrozenV1     bool          `json:"frozen_v1"`
}

type IdentityRecord struct {
	Schema               int    `json:"schema"`
	ID                   string `json:"id"`
	AgeRecipient         string `json:"age_recipient"`
	SSHEd25519Pubkey     string `json:"ssh_ed25519_pubkey"`
	DeployKeyFingerprint string `json:"deploy_key_fingerprint,omitempty"`
	CreatedAt            string `json:"created_at"`
}

func DefaultStoreFormat() StoreFormat {
	return StoreFormat{
		Manifest:      FormatManifest,
		Index:         FormatIndex,
		Object:        FormatObject,
		RoutedRequest: FormatRoutedRequest,
		Request:       "kauket-request-v1",
		Encryption:    "age-v1",
	}
}
