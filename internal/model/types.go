package model

type Vault struct {
	Schema    int                      `json:"schema"`
	StoreID   string                   `json:"store_id"`
	CreatedAt string                   `json:"created_at"`
	UpdatedAt string                   `json:"updated_at"`
	Admins    []AdminRecipient         `json:"admins"`
	Profiles  map[string]Profile       `json:"profiles"`
	Secrets   map[string]Secret        `json:"secrets"`
	Hosts     map[string]Host          `json:"hosts"`
	Requests  map[string]RequestRecord `json:"requests"`
}

type AdminRecipient struct {
	ID        string `json:"id"`
	Recipient string `json:"recipient"`
	CreatedAt string `json:"created_at"`
}

type Profile struct {
	Description string `json:"description"`
}

type Secret struct {
	SecretObjectID string      `json:"secret_object_id"`
	Kind           string      `json:"kind"`
	Profiles       []string    `json:"profiles"`
	Install        InstallSpec `json:"install"`
	ContentBase64  string      `json:"content_base64"`
	SHA256         string      `json:"sha256"`
	CreatedAt      string      `json:"created_at"`
	UpdatedAt      string      `json:"updated_at"`
}

type Host struct {
	DisplayName          string   `json:"display_name"`
	ReportedHostname     string   `json:"reported_hostname"`
	AgeRecipient         string   `json:"age_recipient"`
	DeployKeyFingerprint string   `json:"deploy_key_fingerprint"`
	GrantedProfiles      []string `json:"granted_profiles"`
	GrantedSecrets       []string `json:"granted_secrets"`
	CreatedAt            string   `json:"created_at"`
	ApprovedAt           string   `json:"approved_at"`
}

type RequestRecord struct {
	Status            string   `json:"status"`
	HostID            string   `json:"host_id"`
	RequestedProfiles []string `json:"requested_profiles"`
	CreatedAt         string   `json:"created_at"`
	ApprovedAt        string   `json:"approved_at"`
}

type Bundle struct {
	Schema           int                     `json:"schema"`
	StoreID          string                  `json:"store_id"`
	HostID           string                  `json:"host_id"`
	GeneratedAt      string                  `json:"generated_at"`
	BundleGeneration int                     `json:"bundle_generation"`
	Secrets          map[string]BundleSecret `json:"secrets"`
}

type BundleSecret struct {
	Kind          string      `json:"kind"`
	Install       InstallSpec `json:"install"`
	ContentBase64 string      `json:"content_base64"`
	SHA256        string      `json:"sha256"`
}

type Request struct {
	Schema    int               `json:"schema"`
	StoreID   string            `json:"store_id"`
	RequestID string            `json:"request_id"`
	CreatedAt string            `json:"created_at"`
	Host      RequestHost       `json:"host"`
	Requested RequestedItems    `json:"requested"`
	Signature *RequestSignature `json:"signature,omitempty"`
}

type RequestHost struct {
	ID                 string `json:"id"`
	DisplayName        string `json:"display_name"`
	ReportedHostname   string `json:"reported_hostname"`
	OS                 string `json:"os"`
	Arch               string `json:"arch"`
	AgeRecipient       string `json:"age_recipient"`
	GitDeployPublicKey string `json:"git_deploy_public_key"`
}

type RequestedItems struct {
	Profiles []string `json:"profiles"`
	Secrets  []string `json:"secrets"`
}

type RequestSignature struct {
	Algorithm            string `json:"algorithm"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	SignatureBase64      string `json:"signature_base64"`
}

type InstallSpec struct {
	Destination   string `json:"destination"`
	Mode          string `json:"mode"`
	DirectoryMode string `json:"directory_mode"`
}
