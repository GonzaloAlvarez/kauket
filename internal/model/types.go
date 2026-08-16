package model

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
	Kind               string `json:"kind,omitempty"`
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
	Paths    []string `json:"paths,omitempty"`
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
