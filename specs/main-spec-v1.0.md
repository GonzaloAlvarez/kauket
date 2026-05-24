# Kauket: direct-age, Git-backed, per-host secret bundle manager

## 0. Executive decision

Build **`kauket`** as a Go CLI that uses **direct age encryption**, not SOPS, not GPG, and not a server-side secrets service.

The design should keep kepr's good ideas: Git-native storage, GitHub-assisted bootstrap, opaque storage, request/approval, and a separate local app home. kepr's README and design docs describe those core ideas: serverless GitHub-backed distribution, hardware-oriented identity, Git history, GitOps-style remote access, and a porcelain layer over crypto/Git tooling. ([GitHub](https://github.com/GonzaloAlvarez/kepr/blob/master/README.md "kepr/README.md at master · GonzaloAlvarez/kepr · GitHub")) Kepr's design also already has the important request/approval concept: remote machines create access-request branches and admins review/re-encrypt for approved machines. ([GitHub](https://github.com/GonzaloAlvarez/kepr/blob/master/DESIGN.md "kepr/DESIGN.md at master · GonzaloAlvarez/kepr · GitHub"))

The new tool should **not** keep kepr's GPG/YubiKey-heavy daily flow. It should replace that with:

```text
admin vault.age       encrypted to admin age recipient(s)
host bundle.age       encrypted to one host age recipient + admin recovery recipient(s)
request *.age         encrypted to admin recipient(s)
GitHub/Git            transport only
read-only deploy key  post-approval machine sync
```

This fits the homelab's existing Amun model: Amun is already the provisioning framework and the code in `~/dev/cn-*` / `~/dev/amun-*` is treated as source of truth. The companion memory file also shows that new tools should fit the existing repo/inventory/change-management pattern, with verification after every change.

---

# 1. Product goals

## 1.1 Primary user experience

The intended happy path is exactly:

```sh
# Admin machine
kauket init
kauket add ssh.main_private_key ~/.ssh/main_private_key.pem

# New machine
curl -fsSL https://raw.githubusercontent.com/GonzaloAlvarez/amun/main/install.sh | sh
amun kauket
kauket enroll --request ssh

# Admin machine
kauket approve
```

Interactive approval must look like:

```text
Pending requests:

1. request machine2 2026-05-24-r730xd-debian ssh

approve request 1? [y/N] y
request 1 approved
```

Then:

```sh
# New machine
kauket get ssh.main_private_key
```

Expected output:

```text
syncing store
creating ~/.ssh/main_private_key
```

## 1.2 Security goals

Kauket must:

1. Store no plaintext secrets in Git.
2. Avoid plaintext secret names in Git paths.
3. Avoid plaintext hostnames in Git paths, branch names, deploy-key titles, and commit messages.
4. Avoid plaintext destination paths in Git.
5. Allow per-host intentional grants.
6. Allow machines to sync after approval without broad GitHub user credentials.
7. Allow admin recovery by encrypting each host bundle to admin recipient(s).
8. Never write decrypted secrets except to approved destinations.
9. Never print secret values unless explicitly requested with `--stdout`.
10. Be useful without a maintained secrets server.

Age is the encryption primitive. The official Go package describes age as a simple, modern, secure file encryption tool, format, and Go library with small explicit keys and Unix-style composability. It also exposes Go APIs for X25519 identities and recipients, which is what Kauket should use directly.

## 1.3 Non-goals for v1

Do **not** implement these in v1:

```text
web UI
daemon/server
SOPS support
GPG support
cloud KMS support
multi-user team workflows beyond one admin identity set
automatic secret rotation against third-party providers
Windows support beyond best-effort Go path handling
YubiKey age-plugin support
```

YubiKey support can be a v1.1/v2 feature. Direct `filippo.io/age` is enough for v1. If YubiKey-backed admin recipients are required later, the design can add an external age-plugin execution path.

---

# 2. Naming and repository defaults

## 2.1 Tool name

The binary is:

```sh
kauket
```

Not:

```sh
secret_manager
secrets_manager
kepr2
amun-secret
```

## 2.2 Default store repo

Default GitHub owner:

```text
GonzaloAlvarez
```

Default repo name:

```text
kauket-store
```

Default repo visibility:

```text
private
```

Default remote names:

```text
origin
main
```

All defaults must be overrideable:

```sh
kauket init --owner GonzaloAlvarez --repo kauket-store
kauket init --remote file:///mnt/raidnas/kauket-store.git --no-github
kauket enroll --repo GonzaloAlvarez/kauket-store
```

## 2.3 Environment variables

Support:

```text
KAUKET_HOME       override local app state directory
KAUKET_REPO       default owner/repo, e.g. GonzaloAlvarez/kauket-store
KAUKET_REMOTE     full Git remote URL override
KAUKET_NO_COLOR   disable terminal styling
KAUKET_DEBUG      verbose logs, never secret values
```

`KAUKET_HOME` should mirror kepr's `KEPR_HOME` concept. Kepr already keeps isolated state under its own config directory, which is a good pattern to retain.

---

# 3. Core architecture

## 3.1 High-level model

```text
Admin machine
  has admin age identity
  can decrypt admin/vault.age
  can approve requests
  can rebuild host bundles
  can push to main

New machine
  has host age identity
  has read-only Git deploy key after approval
  can decrypt only its own bundle
  cannot decrypt admin vault
  cannot approve or add secrets
```

## 3.2 Repository layout

The Git repo must look opaque:

```text
kauket-store/
  repo.json
  admin/
    vault.age
  bundles/
    h_7j4v6m2q9xk3p8da.age
    h_b2n8w5s6c1t9qq0r.age
  requests/
    .keep
```

Request branches add:

```text
requests/
  rq_m5w8r0qf2p1x9z6a.age
```

No file or directory name may include:

```text
ssh
aws
cloudflare
headscale
tailscale
grafana
r730xd
kaiser
machine2
hostname
private_key
credentials
```

## 3.3 Public repo metadata: `repo.json`

This file is public metadata. It must not contain hostnames or secret names.

```json
{
  "schema": 1,
  "store_id": "ks_6me7bk1f9s4xz2qa",
  "created_at": "2026-05-24T00:00:00Z",
  "format": {
    "admin_vault": "kauket-admin-vault-v1",
    "host_bundle": "kauket-host-bundle-v1",
    "request": "kauket-request-v1",
    "encryption": "age-v1"
  },
  "github": {
    "owner": "GonzaloAlvarez",
    "repo": "kauket-store",
    "default_branch": "main"
  },
  "admin_recipients": [
    {
      "id": "ar_3m0vq2ks9p8n1c7x",
      "recipient": "age1..."
    }
  ]
}
```

Allowed plaintext in `repo.json`:

```text
schema version
store ID
format names
GitHub owner/repo
admin public age recipients
```

Disallowed plaintext in `repo.json`:

```text
secret IDs
hostnames
machine nicknames
destination paths
profiles like ssh/aws
user email addresses unless unavoidable
```

## 3.4 Local admin state

Admin local state:

```text
~/.config/kauket/
  config.json
  identities/
    admin.txt
  repo/
    .git/
    repo.json
    admin/vault.age
    bundles/...
```

Example `config.json`:

```json
{
  "schema": 1,
  "role": "admin",
  "store_id": "ks_6me7bk1f9s4xz2qa",
  "repo": {
    "owner": "GonzaloAlvarez",
    "name": "kauket-store",
    "remote_https": "https://github.com/GonzaloAlvarez/kauket-store.git",
    "remote_ssh": "git@github.com:GonzaloAlvarez/kauket-store.git",
    "default_branch": "main"
  },
  "admin": {
    "recipient_id": "ar_3m0vq2ks9p8n1c7x",
    "identity_path": "identities/admin.txt"
  }
}
```

Permissions:

```text
~/.config/kauket                  0700
~/.config/kauket/config.json      0600
~/.config/kauket/identities       0700
~/.config/kauket/identities/*.txt 0600
```

## 3.5 Local client state

Client local state after `kauket enroll`:

```text
~/.config/kauket/
  config.json
  identities/
    host.txt
  git/
    deploy_key
    deploy_key.pub
  repo/
    .git/
    repo.json
    bundles/...
  state/
    installed.json
```

Example `config.json`:

```json
{
  "schema": 1,
  "role": "client",
  "store_id": "ks_6me7bk1f9s4xz2qa",
  "host": {
    "id": "h_7j4v6m2q9xk3p8da",
    "display_name": "machine2",
    "identity_path": "identities/host.txt",
    "deploy_key_path": "git/deploy_key"
  },
  "repo": {
    "owner": "GonzaloAlvarez",
    "name": "kauket-store",
    "remote_https": "https://github.com/GonzaloAlvarez/kauket-store.git",
    "remote_ssh": "git@github.com:GonzaloAlvarez/kauket-store.git",
    "default_branch": "main"
  }
}
```

A machine whose first operation is `enroll` must be marked:

```json
"role": "client"
```

Client role may run:

```text
kauket enroll
kauket get
kauket list
kauket status
kauket sync
```

Client role must not run:

```text
kauket add
kauket approve
kauket rotate
kauket rebuild-bundles
```

If a client later runs `kauket init`, Kauket must not silently convert the machine into an admin. It must either initialize a new store in a clean `KAUKET_HOME`, or fail with a clear message unless an explicit future `promote-admin` flow is implemented.

---

# 4. Encryption format

## 4.1 Use Go age library directly

Use:

```go
filippo.io/age
```

Do **not** shell out to `age` for v1 unless a test explicitly validates CLI compatibility.

Do **not** use:

```text
sops
gpg
openssl
custom crypto
passphrase-only age mode
```

Age supports direct file encryption to recipients and decryption with identity files; its documented CLI model is `age -r RECIPIENT ...` and `age --decrypt -i PATH ...`, and the Go package exposes corresponding recipient/identity APIs.

## 4.2 Identity generation

Admin init:

```text
Generate age X25519 identity.
Write identity to ~/.config/kauket/identities/admin.txt.
Write public recipient to repo.json.
```

Client enroll:

```text
Generate age X25519 identity.
Write identity to ~/.config/kauket/identities/host.txt.
Include public recipient in encrypted request.
```

Implementation detail:

```go
identity, err := age.GenerateX25519Identity()
recipient := identity.Recipient().String()
```

## 4.3 Admin vault plaintext schema

Before encryption, `admin/vault.age` plaintext is canonical JSON:

```json
{
  "schema": 1,
  "store_id": "ks_6me7bk1f9s4xz2qa",
  "created_at": "2026-05-24T00:00:00Z",
  "updated_at": "2026-05-24T00:00:00Z",
  "admins": [
    {
      "id": "ar_3m0vq2ks9p8n1c7x",
      "recipient": "age1...",
      "created_at": "2026-05-24T00:00:00Z"
    }
  ],
  "profiles": {
    "ssh": {
      "description": "SSH bootstrap profile"
    }
  },
  "secrets": {
    "ssh.main_private_key": {
      "secret_object_id": "s_q8x4c9vy2m7k1w0z",
      "kind": "file",
      "profiles": ["ssh"],
      "install": {
        "destination": "~/.ssh/main_private_key",
        "mode": "0600",
        "directory_mode": "0700"
      },
      "content_base64": "BASE64",
      "sha256": "hex",
      "created_at": "2026-05-24T00:00:00Z",
      "updated_at": "2026-05-24T00:00:00Z"
    }
  },
  "hosts": {
    "h_7j4v6m2q9xk3p8da": {
      "display_name": "machine2",
      "reported_hostname": "r730xd-debian",
      "age_recipient": "age1...",
      "deploy_key_fingerprint": "SHA256:...",
      "granted_profiles": ["ssh"],
      "granted_secrets": [],
      "created_at": "2026-05-24T00:00:00Z",
      "approved_at": "2026-05-24T00:00:00Z"
    }
  },
  "requests": {
    "rq_m5w8r0qf2p1x9z6a": {
      "status": "approved",
      "host_id": "h_7j4v6m2q9xk3p8da",
      "requested_profiles": ["ssh"],
      "created_at": "2026-05-24T00:00:00Z",
      "approved_at": "2026-05-24T00:00:00Z"
    }
  }
}
```

This file is encrypted to admin recipients only.

## 4.4 Host bundle plaintext schema

Before encryption, a host bundle is canonical JSON:

```json
{
  "schema": 1,
  "store_id": "ks_6me7bk1f9s4xz2qa",
  "host_id": "h_7j4v6m2q9xk3p8da",
  "generated_at": "2026-05-24T00:00:00Z",
  "bundle_generation": 4,
  "secrets": {
    "ssh.main_private_key": {
      "kind": "file",
      "install": {
        "destination": "~/.ssh/main_private_key",
        "mode": "0600",
        "directory_mode": "0700"
      },
      "content_base64": "BASE64",
      "sha256": "hex"
    }
  }
}
```

This file is encrypted to:

```text
host age recipient
all admin recovery recipients
```

## 4.5 Request plaintext schema

Before encryption, a request is canonical JSON:

```json
{
  "schema": 1,
  "store_id": "ks_6me7bk1f9s4xz2qa",
  "request_id": "rq_m5w8r0qf2p1x9z6a",
  "created_at": "2026-05-24T00:00:00Z",
  "host": {
    "id": "h_7j4v6m2q9xk3p8da",
    "display_name": "machine2",
    "reported_hostname": "r730xd-debian",
    "os": "linux",
    "arch": "amd64",
    "age_recipient": "age1...",
    "git_deploy_public_key": "ssh-ed25519 AAAA..."
  },
  "requested": {
    "profiles": ["ssh"],
    "secrets": []
  },
  "signature": {
    "algorithm": "ed25519",
    "public_key_fingerprint": "SHA256:...",
    "signature_base64": "BASE64"
  }
}
```

The request is encrypted to admin recipients from `repo.json`.

The signature must cover the canonical request payload excluding the `signature` field. Use the generated Ed25519 Git deploy private key to sign the payload. This cryptographically binds the deploy key, age recipient, host ID, hostname, and requested profile together.

## 4.6 Padding

Before age encryption, wrap plaintext as:

```json
{
  "payload": { "...": "..." },
  "padding_base64": "random bytes"
}
```

Pad to size classes:

```text
16 KiB
64 KiB
256 KiB
1 MiB
4 MiB
```

Rules:

```text
Choose smallest class that fits plaintext.
Use crypto/rand for padding.
Reject payloads larger than 4 MiB unless --max-size is raised.
Do not compress in v1 unless tests prove deterministic behavior.
```

Compression can be added later. Padding is more important than compression for metadata privacy.

---

# 5. Git and GitHub model

## 5.1 Kauket manages Git internally

The user must never need to run:

```sh
git pull
git push
git checkout
gh repo create
gh repo deploy-key add
```

Kauket performs all sync internally.

## 5.2 Git implementation choice

Use `go-git` for clone, fetch, checkout, commit, and push unless it blocks deploy-key SSH support. Kepr already depends on `go-git`, `google/go-github`, `github.com/cli/oauth`, and Cobra, so those are reasonable libraries to reuse or mirror.

If `go-git` creates too much friction for SSH deploy keys, use system `git` behind an interface. The CLI still owns the workflow; the user must not run Git manually.

## 5.3 Auth provider order

For admin operations:

1. If `gh` exists and is authenticated, use `gh`.
2. Else use GitHub OAuth device flow.
3. Else fail with actionable instructions.

The GitHub CLI manual says `gh auth status` displays the active account and authentication state, and `gh auth token` prints the token for the active account.

For new machine enrollment:

1. If `gh` exists and authenticated, use `gh` token temporarily to push request branch.
2. Else use GitHub device flow temporarily to push request branch.
3. After approval, use a read-only deploy key for all future sync.
4. Do not retain broad GitHub user tokens on clients if the deploy key has been installed and verified.

GitHub's docs describe device flow as intended for headless apps such as CLI tools, and note that the client secret is not needed for device flow.

## 5.4 Repository creation

`kauket init` should:

1. Detect or obtain a GitHub token.
2. Create private repo `GonzaloAlvarez/kauket-store` unless it already exists.
3. Clone it into `~/.config/kauket/repo`.
4. Write `repo.json`.
5. Write encrypted `admin/vault.age`.
6. Commit and push.

If `gh` is installed, Kauket may shell out to:

```sh
gh repo create GonzaloAlvarez/kauket-store --private
```

or use the token from `gh auth token` and create the repo through GitHub's API. The GitHub CLI manual documents `gh repo create` for noninteractive repository creation with `--public`, `--private`, or `--internal`.

## 5.5 Deploy keys

Enrollment must generate a Git SSH keypair:

```text
~/.config/kauket/git/deploy_key
~/.config/kauket/git/deploy_key.pub
```

On approval, the admin must add the public key as a **read-only deploy key** to the GitHub repo.

Deploy-key title must be opaque:

```text
kauket h_7j4v6m2q9xk3p8da
```

Not:

```text
kauket machine2 r730xd-debian
```

GitHub docs describe deploy keys as SSH keys granting access to a single repository, and the GitHub CLI supports adding deploy keys. The CLI's deploy-key command only grants write access if `--allow-write` is used, so Kauket must not pass that flag for clients.

## 5.6 Branch model

Main branch:

```text
main
```

Request branches:

```text
request/rq_m5w8r0qf2p1x9z6a
```

Never:

```text
request/machine2
request/r730xd-debian
request/ssh
```

Request branch contains only:

```text
requests/rq_m5w8r0qf2p1x9z6a.age
```

Approval flow:

```text
fetch request/*
decrypt request files
show pending requests
approve selected request
update admin/vault.age
write bundles/h_....age
commit to main with generic message
push main
delete request branch
```

Commit messages must be generic:

```text
kauket: initialize store
kauket: update vault
kauket: update bundle
kauket: approve request
```

Never:

```text
approve machine2 ssh
grant r730xd ssh private key
add aws primary credentials
```

---

# 6. CLI specification

## 6.1 Required commands for v1

```sh
kauket init
kauket add <secret-id> <source-file>
kauket enroll --request <profile>
kauket approve
kauket get <secret-id>
kauket list
kauket status
kauket sync
kauket version
```

## 6.2 `kauket init`

### Usage

```sh
kauket init [flags]
```

Flags:

```text
--owner string          default GonzaloAlvarez
--repo string           default kauket-store
--private              default true
--remote string         explicit Git remote
--no-github             use local/non-GitHub remote
--admin-identity path   import existing age identity
--yes                  noninteractive
```

### Behavior

If no existing store:

```text
create KAUKET_HOME
generate admin age identity unless --admin-identity supplied
authenticate to GitHub via gh or device flow unless --no-github
create repo if needed
clone repo
write repo.json
create empty admin vault
commit
push
```

If existing store:

```text
clone/fetch repo
read repo.json
if admin identity can decrypt admin/vault.age, attach as admin
else fail with explanation
```

### Required output

```text
initialized kauket store GonzaloAlvarez/kauket-store
admin recipient ar_3m0vq2ks9p8n1c7x created
```

### Failure cases

If `gh` is installed but authenticated as a different user than `--owner`, warn and require confirmation unless `--yes`.

If repo already exists but is not a Kauket repo, fail.

If `KAUKET_HOME` exists with client role, fail unless `--force-new-store` is added in a future release.

## 6.3 `kauket add`

### Usage

```sh
kauket add <secret-id> <source-file> [flags]
```

Flags:

```text
--dest string           destination path on target machines
--mode string           default inferred
--directory-mode string default inferred
--profile string        repeatable
--force                 replace existing secret
```

### Example

```sh
kauket add ssh.main_private_key ~/.ssh/main_private_key.pem
```

### Secret ID validation

Valid:

```text
ssh.main_private_key
aws.primary_account.key_file
cloudflare.dns_api_token
```

Invalid:

```text
ssh/main_private_key
../ssh.key
SSH.Main
ssh.main-private-key
ssh main
```

Regex:

```text
^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$
```

### Destination inference

If `--dest` omitted:

```text
ssh.*_private_key       ~/.ssh/<last segment>
aws.*.key_file          ~/.aws/credentials
*.kubeconfig            ~/.kube/config
```

For:

```text
ssh.main_private_key
```

Destination becomes:

```text
~/.ssh/main_private_key
```

If no rule matches and `--dest` is absent, fail:

```text
no destination rule for secret "foo.bar"; pass --dest
```

### Profile inference

If `--profile` omitted:

```text
ssh.*                   profile ssh
aws.*                   profile aws
*.kubeconfig            profile kube
```

### Behavior

```text
sync main
decrypt admin vault
read source file
validate file size <= 4 MiB default
compute sha256
add/update secret in vault
rebuild bundles for hosts whose grants match this secret
encrypt admin vault
commit
push
```

### Required output

```text
added ssh.main_private_key
updated 0 host bundles
```

or:

```text
updated ssh.main_private_key
updated 3 host bundles
```

## 6.4 `kauket enroll`

### Usage

```sh
kauket enroll --request <profile> [flags]
```

Flags:

```text
--request string        repeatable; profile requested, e.g. ssh
--name string           default local hostname short name
--repo string           owner/repo
--remote string         explicit remote
--offline               print request code instead of pushing branch
--yes                  noninteractive
```

### Behavior

```text
create client KAUKET_HOME if absent
generate host age identity if absent
generate Ed25519 SSH deploy key if absent
read repo.json
build request object
sign request object with deploy key
encrypt request to admin recipients
push request branch request/rq_<random>
write local client config
```

If no `gh` and no stored token, invoke GitHub device flow.

If device flow is used, token is temporary and must not remain after request submission unless required for private repo fetch before approval. After approval and deploy-key verification, delete broad user token.

### Required output

```text
created enrollment request rq_m5w8r0qf2p1x9z6a
requested profiles: ssh
waiting for approval
```

If offline:

```text
created offline enrollment request

kauket approve --request-code <code>
```

## 6.5 `kauket approve`

### Usage

```sh
kauket approve [flags]
```

Flags:

```text
--request string        approve a specific request id
--all                  approve all pending requests
--yes                  noninteractive
--dry-run              show actions only
```

### Interactive behavior

```text
syncing store
fetching pending requests

Pending requests:

1. request machine2 2026-05-24-r730xd-debian ssh

approve request 1? [y/N] y
request 1 approved
```

### Approval behavior

For each approved request:

```text
verify request decrypts with admin identity
verify request signature with included deploy public key
check request store_id matches repo.json
check host_id is not already assigned to a different key
add host to admin vault
grant requested profiles
add read-only GitHub deploy key
build host bundle
encrypt host bundle to host recipient + admin recipients
commit generic update to main
push main
delete remote request branch
```

### Deploy key failure

If deploy key creation fails, do not mark approved.

If vault/bundle commit succeeds but deploy key creation fails, rollback local changes or leave the repo unchanged. Approval must be atomic from the user's perspective.

## 6.6 `kauket get`

### Usage

```sh
kauket get <secret-id> [flags]
```

Flags:

```text
--stdout               print secret to stdout instead of installing
--force                overwrite local untracked destination
--backup               create timestamped backup before overwrite
--no-sync              do not sync first
```

### Behavior

```text
sync main unless --no-sync
load client config
find bundles/<host_id>.age
decrypt with host identity
find secret-id in bundle
if --stdout, print content only
else install according to bundle metadata
write installed state
```

### Required output

First install:

```text
syncing store
creating ~/.ssh/main_private_key
```

Already current:

```text
syncing store
~/.ssh/main_private_key already current
```

Not granted:

```text
secret ssh.main_private_key is not granted to this machine
```

No approved bundle yet:

```text
no approved bundle found for this machine
request is pending or has not been approved
```

## 6.7 `kauket list`

Client output:

```text
ssh.main_private_key
```

Admin output:

```text
ssh.main_private_key  profiles=ssh  hosts=1
```

Do not show content hashes by default.

## 6.8 `kauket status`

Client output:

```text
role: client
store: GonzaloAlvarez/kauket-store
host_id: h_7j4v6m2q9xk3p8da
bundle: present
last_sync: 2026-05-24T14:12:31-04:00
```

Admin output:

```text
role: admin
store: GonzaloAlvarez/kauket-store
secrets: 1
hosts: 1
pending_requests: 0
```

---

# 7. File installation rules

## 7.1 Atomic write

For file secrets:

```text
expand destination
create parent directory with directory_mode
write temp file in same directory
fsync temp file
chmod temp file
rename temp file into destination
fsync parent directory where supported
record installed hash
```

## 7.2 Symlink protection

Default behavior:

```text
refuse to write if destination path or parent path contains a symlink
```

No `--follow-symlink` in v1.

## 7.3 Existing file behavior

If destination does not exist:

```text
write file
```

If destination exists and content hash matches:

```text
do nothing
```

If destination exists and Kauket previously installed same destination but old hash differs:

```text
replace atomically
```

If destination exists and Kauket did not install it:

```text
fail unless --force or --backup
```

With `--backup`:

```text
~/.ssh/main_private_key.kauket-bak-20260524T141233
```

## 7.4 Installed state

`~/.config/kauket/state/installed.json`:

```json
{
  "schema": 1,
  "installed": {
    "ssh.main_private_key": {
      "destination": "~/.ssh/main_private_key",
      "expanded_destination": "/home/gonzalo/.ssh/main_private_key",
      "sha256": "hex",
      "installed_at": "2026-05-24T00:00:00Z"
    }
  }
}
```

---

# 8. Amun integration

## 8.1 Required Amun command

Add an Amun integration so this works:

```sh
amun kauket
```

Amun already emphasizes one-line install, modular provisioning, idempotent operations, and reproducible setup, so Kauket should be packaged as an Amun-installed bootstrap utility rather than a standalone manual process.

## 8.2 What `amun kauket` does

`amun kauket` must:

```text
install kauket binary
install git/ssh prerequisites if missing
create ~/.config/kauket with 0700
write bootstrap config if repo info is known
print next command
```

Expected output:

```text
kauket installed
next: kauket enroll --request ssh
```

## 8.3 Install source

Preferred:

```text
GitHub release binary for OS/arch
```

Fallback:

```text
go install github.com/GonzaloAlvarez/kauket/cmd/kauket@latest
```

## 8.4 Idempotence

Running this repeatedly must be safe:

```sh
amun kauket
amun kauket
amun kauket
```

It must not delete existing Kauket identities.

---

# 9. Recommendations from kepr

## 9.1 Keep from kepr

Keep these concepts:

|Kepr concept|Kauket adaptation|
|---|---|
|Cobra CLI|Use Cobra or similar, but keep commands simpler|
|App dependency injection|Keep `App`/dependency struct pattern for testability|
|Separate app home|`KAUKET_HOME`, not `~/.gnupg` or random dotfiles|
|GitHub device flow|Use for init/enroll fallback when `gh` is absent|
|GitOps request approval|Keep, but request branches are random and encrypted|
|Opaque storage instinct|Use opaque host IDs and request IDs|
|Workflow tests|Keep stateful command testing and retry testing|

Kepr's `cmd.App` pattern injects shell, UI, and GitHub dependencies, which is useful for tests and should be retained in spirit. Kepr also already has request workflow code that validates, pulls, checks access, creates a branch, builds a request, and commits/pushes; the new implementation should preserve that lifecycle but simplify the crypto and storage model.

## 9.2 Change from kepr

Do not keep these:

|Kepr behavior|Kauket replacement|
|---|---|
|GPG encryption|Direct age|
|YubiKey daily dependency|Host age identity for daily decrypt|
|`.gpg.id` recipient files|Admin vault + generated host bundles|
|Per-secret directory tree|Per-host opaque bundle|
|Request branch with hostname|Random request branch|
|Machine write credentials after approval|Read-only deploy key|
|Secret retrieval to stdout by default|Install to declared destination by default|
|Generic password manager semantics|Bootstrap-file installer semantics|

Kepr's store uses `.gpg.id` files and UUID-based directories, with GPG recipients inherited through directories. Kauket should keep the opaque-ID lesson but not the `.gpg.id` tree.

## 9.3 Do not copy kepr's file header pattern

The new code should not add large boilerplate comments to every Go file. Keep licensing in `LICENSE`. Add file headers only if legally required.

---

# 10. Go implementation standards

## 10.1 Style guide

Follow Google Go style and Go Code Review Comments.

Google's Go style guide emphasizes simplicity, avoiding unnecessary abstraction, useful errors, and comments that explain why rather than what. The Go Code Review Comments page is the standard companion checklist for Go idioms such as `gofmt`, error strings, interfaces, package names, useful test failures, and variable names.

## 10.2 Comment policy

The user preference is: **do not add comments unless required**.

Implementation rule:

```text
No narrative comments.
No inline comments explaining obvious code.
No file-level boilerplate comments unless legally required.
Prefer unexported symbols to avoid doc-comment requirements.
For unavoidable exported symbols, add the minimal Go doc comment required by Go tooling/style.
Allow //go: directives when needed.
Allow generated-code markers only in generated files.
```

So this is acceptable only if exported:

```go
// Store manages a local Kauket checkout.
type Store struct { ... }
```

But prefer:

```go
type store struct { ... }
```

and no comment.

## 10.3 Package layout

Use mostly `internal`.

```text
kauket/
  go.mod
  cmd/
    kauket/
      main.go
  internal/
    agebox/
      agebox.go
      agebox_test.go
    app/
      app.go
    bundle/
      bundle.go
      bundle_test.go
    cli/
      root.go
      init.go
      add.go
      enroll.go
      approve.go
      get.go
    config/
      config.go
      paths.go
      config_test.go
    gitstore/
      store.go
      sync.go
      request_branch.go
      deploy_key.go
      store_test.go
    githubauth/
      gh.go
      device.go
      token.go
    install/
      file.go
      file_test.go
    model/
      ids.go
      vault.go
      request.go
      bundle.go
    ui/
      terminal.go
      fake.go
    testutil/
      homes.go
      git.go
      keys.go
  e2e/
    local_test.go
    github_test.go
  scripts/
    verify.sh
    check-comments.sh
```

Avoid a public `pkg/` directory unless an external API is intentionally supported. Kauket is a CLI tool, not a library.

## 10.4 Dependencies

Required:

```text
filippo.io/age
github.com/spf13/cobra
github.com/go-git/go-git/v5
github.com/google/go-github/v67 or current
github.com/cli/oauth
golang.org/x/crypto/ssh
golang.org/x/term
```

Optional:

```text
github.com/gofrs/flock or simple lockfile implementation
```

Avoid unnecessary TUI libraries in v1. Deterministic output matters for tests.

---

# 11. Internal APIs

## 11.1 `internal/model`

Types:

```go
type Vault struct
type Secret struct
type Host struct
type Request struct
type Bundle struct
type InstallSpec struct
```

Important functions:

```go
func NewHostID() string
func NewRequestID() string
func NewStoreID() string
func ValidateSecretID(id string) error
func InferInstallSpec(secretID, sourcePath string) (InstallSpec, error)
```

## 11.2 `internal/agebox`

Functions:

```go
func GenerateIdentity() (Identity, error)
func ParseIdentity(data []byte) (Identity, error)
func Encrypt(plaintext []byte, recipients []string) ([]byte, error)
func Decrypt(ciphertext []byte, identities [][]byte) ([]byte, error)
```

Requirements:

```text
Use crypto/rand only.
Return useful errors.
Do not log plaintext.
Do not log recipients at debug unless explicitly redacted.
```

## 11.3 `internal/bundle`

Functions:

```go
func EncodeVault(v Vault, recipients []string) ([]byte, error)
func DecodeVault(ciphertext []byte, identities [][]byte) (Vault, error)
func BuildHostBundle(v Vault, hostID string) (Bundle, error)
func EncodeHostBundle(b Bundle, recipients []string) ([]byte, error)
func DecodeHostBundle(ciphertext []byte, identities [][]byte) (Bundle, error)
func EncodeRequest(r Request, adminRecipients []string) ([]byte, error)
func DecodeRequest(ciphertext []byte, adminIdentities [][]byte) (Request, error)
```

## 11.4 `internal/gitstore`

Functions:

```go
func OpenOrClone(ctx context.Context, cfg Config, auth Auth) (*Store, error)
func (s *Store) Sync(ctx context.Context) error
func (s *Store) CommitAndPush(ctx context.Context, message string) error
func (s *Store) PushRequest(ctx context.Context, requestID string, data []byte) error
func (s *Store) FetchRequests(ctx context.Context) ([]RequestRef, error)
func (s *Store) DeleteRequestBranch(ctx context.Context, requestID string) error
```

Requirements:

```text
All branch names random.
All commit messages generic.
No tokens in remote URLs.
No hostnames in Git metadata.
Use a lock around operations.
Retry non-fast-forward pushes at most twice.
```

## 11.5 `internal/install`

Functions:

```go
func InstallFile(home string, id string, content []byte, spec InstallSpec, opts Options) (Result, error)
```

Tests must cover symlink attacks, existing files, force, backup, mode, and directory creation.

---

# 12. Error handling and exit codes

Exit codes:

```text
0 success
1 usage/user error
2 crypto/decryption/integrity error
3 sync/Git/GitHub error
4 install/filesystem permission error
5 not approved/not granted
```

Examples:

```text
error: secret id "ssh/main" is invalid
error: no approved bundle found for this machine
error: destination ~/.ssh/main_private_key exists and was not installed by kauket
error: failed to decrypt bundle; this machine is probably not approved
error: GitHub authentication required; run gh auth login or complete device flow
```

Never print:

```text
secret content
full GitHub token
age identity secret
deploy private key
```

---

# 13. Verification plan

Verification is mandatory. The feature is not done until every relevant check passes.

## 13.1 Unit tests

Run:

```sh
go test ./...
go test -race ./...
go vet ./...
```

### ID validation tests

Cases:

```text
ssh.main_private_key                valid
aws.primary_account.key_file        valid
cloudflare.dns_api_token            valid
ssh/main_private_key                invalid
../ssh.main_private_key             invalid
ssh..main                           invalid
SSH.main                            invalid
ssh.main-private-key                invalid
ssh main                            invalid
```

### Destination inference tests

```text
ssh.main_private_key + ~/.ssh/main_private_key.pem
  -> ~/.ssh/main_private_key, 0600, dir 0700, profile ssh

aws.primary_account.key_file + /tmp/credentials
  -> ~/.aws/credentials, 0600, dir 0700, profile aws

foo.bar + /tmp/value
  -> error without --dest
```

### Age tests

Generate two identities:

```text
admin
host
```

Verify:

```text
encrypt to host only -> host decrypts, admin fails
encrypt to host+admin -> both decrypt
wrong identity fails
corrupted ciphertext fails
empty recipient list fails
```

### Bundle tests

Test:

```text
vault encode/decode round trip
request encode/decode round trip
host bundle includes granted profile
host bundle excludes ungranted profile
host bundle includes explicit granted secret
host bundle excludes all other secrets
padding size class applied
plaintext secret name not present in ciphertext bytes
plaintext content not present in ciphertext bytes
```

### Git metadata tests

For generated branch names and commit messages, verify they do not contain:

```text
secret ID
profile name
hostname
display name
destination path
```

### Install tests

Use temp HOME.

Test:

```text
creates ~/.ssh with 0700
creates private key with 0600
does not rewrite if already current
fails on existing unmanaged different file
--backup creates backup
--force overwrites
refuses destination symlink
refuses parent symlink
refuses path traversal
does not leave partial file after simulated write failure
```

### GitHub auth provider tests

Mock `gh`.

Cases:

```text
gh not installed -> device provider selected
gh installed but auth status fails -> device provider selected
gh installed and token available -> gh provider selected
gh token command prints token -> token captured without logging
```

## 13.2 Local end-to-end test

This test must use a real Kauket binary, a real local bare Git repo, real age encryption, and real file installation.

### Script

```sh
set -euo pipefail

ROOT="$(mktemp -d)"
REMOTE="$ROOT/kauket-store.git"
ADMIN_HOME="$ROOT/admin-home"
MACHINE_HOME="$ROOT/machine2-home"

mkdir -p "$ADMIN_HOME" "$MACHINE_HOME"
git init --bare "$REMOTE"

go build -o "$ROOT/kauket" ./cmd/kauket

KAUKET_HOME="$ADMIN_HOME/.config/kauket" \
HOME="$ADMIN_HOME" \
"$ROOT/kauket" init --remote "file://$REMOTE" --no-github --yes

mkdir -p "$ADMIN_HOME/.ssh"
ssh-keygen -t ed25519 -N "" -f "$ADMIN_HOME/.ssh/main_private_key.pem"

KAUKET_HOME="$ADMIN_HOME/.config/kauket" \
HOME="$ADMIN_HOME" \
"$ROOT/kauket" add ssh.main_private_key "$ADMIN_HOME/.ssh/main_private_key.pem"

KAUKET_HOME="$MACHINE_HOME/.config/kauket" \
HOME="$MACHINE_HOME" \
"$ROOT/kauket" enroll --remote "file://$REMOTE" --request ssh --name machine2 --yes

KAUKET_HOME="$ADMIN_HOME/.config/kauket" \
HOME="$ADMIN_HOME" \
"$ROOT/kauket" approve --all --yes

KAUKET_HOME="$MACHINE_HOME/.config/kauket" \
HOME="$MACHINE_HOME" \
"$ROOT/kauket" get ssh.main_private_key

test -f "$MACHINE_HOME/.ssh/main_private_key"
ssh-keygen -y -f "$MACHINE_HOME/.ssh/main_private_key" >/dev/null
cmp "$ADMIN_HOME/.ssh/main_private_key.pem" "$MACHINE_HOME/.ssh/main_private_key"
```

### Permission verification

Linux:

```sh
test "$(stat -c %a "$MACHINE_HOME/.ssh")" = "700"
test "$(stat -c %a "$MACHINE_HOME/.ssh/main_private_key")" = "600"
```

macOS:

```sh
test "$(stat -f %Lp "$MACHINE_HOME/.ssh")" = "700"
test "$(stat -f %Lp "$MACHINE_HOME/.ssh/main_private_key")" = "600"
```

The test helper should abstract the `stat` difference.

### Metadata leak verification

After the local E2E test, inspect the admin checkout repo:

```sh
CHECKOUT="$ADMIN_HOME/.config/kauket/repo"

! grep -R -I -i "ssh.main_private_key" "$CHECKOUT"
! grep -R -I -i "main_private_key" "$CHECKOUT"
! grep -R -I -i "machine2" "$CHECKOUT"
! grep -R -I -i "r730xd" "$CHECKOUT"
! grep -R -I -i "BEGIN OPENSSH" "$CHECKOUT"
```

Allowed exceptions:

```text
test logs outside repo
local config outside repo
```

No exception inside the Git working tree.

## 13.3 Negative E2E tests

### Unapproved machine cannot get secret

```sh
kauket enroll --request ssh
kauket get ssh.main_private_key
```

Expected:

```text
no approved bundle found for this machine
```

Exit code:

```text
5
```

### Wrong host cannot decrypt bundle

Create two clients:

```text
machine2
machine3
```

Approve only machine2.

Copy machine2 bundle to machine3's host ID path or point machine3 at machine2 bundle.

Expected:

```text
failed to decrypt bundle
```

No destination file created.

### Existing unmanaged file protection

Before `kauket get`:

```sh
mkdir -p "$MACHINE_HOME/.ssh"
echo "do not overwrite" > "$MACHINE_HOME/.ssh/main_private_key"
chmod 600 "$MACHINE_HOME/.ssh/main_private_key"
```

Run:

```sh
kauket get ssh.main_private_key
```

Expected failure:

```text
destination exists and was not installed by kauket
```

Then:

```sh
kauket get ssh.main_private_key --backup
```

Expected:

```text
backup created
creating ~/.ssh/main_private_key
```

Verify backup content is `do not overwrite`.

### Symlink attack

```sh
mkdir -p "$MACHINE_HOME/.ssh"
ln -s /tmp/evil "$MACHINE_HOME/.ssh/main_private_key"
kauket get ssh.main_private_key
```

Expected:

```text
refusing to write through symlink
```

No `/tmp/evil` written.

### Corrupt bundle

Flip one byte in bundle.

Expected:

```text
failed to decrypt bundle
```

No install.

## 13.4 "Real data" tests

Use real generated material, not production secrets.

### Real SSH private key

```sh
ssh-keygen -t ed25519 -N "" -f "$ADMIN_HOME/.ssh/main_private_key.pem"
kauket add ssh.main_private_key "$ADMIN_HOME/.ssh/main_private_key.pem"
kauket get ssh.main_private_key
ssh-keygen -y -f "$MACHINE_HOME/.ssh/main_private_key" >/dev/null
```

### Real AWS credentials file format

Create:

```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

Run:

```sh
kauket add aws.primary_account.key_file "$ADMIN_HOME/aws_credentials" --dest ~/.aws/credentials --profile aws
kauket enroll --request aws
kauket approve --all --yes
kauket get aws.primary_account.key_file
```

Verify:

```sh
test -f "$MACHINE_HOME/.aws/credentials"
grep -q "aws_access_key_id" "$MACHINE_HOME/.aws/credentials"
```

Then metadata scan:

```sh
! grep -R -I -i "AKIAIOSFODNN7EXAMPLE" "$ADMIN_HOME/.config/kauket/repo"
! grep -R -I -i "aws.primary_account" "$ADMIN_HOME/.config/kauket/repo"
```

### Binary file

Generate:

```sh
dd if=/dev/urandom of="$ADMIN_HOME/blob.bin" bs=1024 count=32
kauket add binary.test_blob "$ADMIN_HOME/blob.bin" --dest ~/.local/share/test_blob --profile test
```

Approve/get and `cmp`.

## 13.5 GitHub E2E test

This must be gated so it never runs accidentally:

```sh
KAUKET_GITHUB_E2E=1
KAUKET_GITHUB_OWNER=GonzaloAlvarez
KAUKET_GITHUB_REPO=kauket-e2e-$(date +%s)
```

Prerequisite:

```sh
gh auth status
```

Test:

```sh
go test ./e2e -run TestGitHubInitEnrollApproveGet -count=1
```

The test must:

```text
create private GitHub repo
run kauket init using gh credentials
add generated SSH private key
enroll machine using request branch
approve request
verify read-only deploy key exists
verify machine can sync using deploy key
verify machine cannot push to main
get secret
verify installed file
scan repo for metadata leaks
delete test repo
```

If cleanup fails, print exact repo name.

## 13.6 Manual device-flow test

Because device flow requires human interaction, provide a manual test:

```sh
PATH="/usr/bin:/bin" KAUKET_HOME="$TMP/admin" HOME="$TMP/admin" kauket init
```

Expected:

```text
Open https://github.com/login/device
Enter code XXXX-XXXX
```

After completion:

```text
initialized kauket store ...
```

Repeat for enroll with `gh` hidden from `PATH`.

Device-flow implementation must follow GitHub's device-flow rules for CLI/headless apps.

## 13.7 Amun verification

On a clean VM or container:

```sh
curl -fsSL https://raw.githubusercontent.com/GonzaloAlvarez/amun/main/install.sh | sh
amun kauket
kauket version
kauket status
```

Expected:

```text
kauket installed
role: uninitialized
```

Then run full local E2E with two separate `HOME` directories.

Amun's own docs say it supports end-to-end provisioning tests and Molecule-based role tests, so Kauket should mirror that style with both local tests and real bootstrap tests.

---

# 14. CI requirements

GitHub Actions matrix:

```text
ubuntu-latest amd64
macos-latest arm64
```

Jobs:

```sh
gofmt check
go test ./...
go test -race ./...
go vet ./...
staticcheck ./...
govulncheck ./...
scripts/check-comments.sh
scripts/e2e-local.sh
```

Release job:

```text
build linux/amd64
build linux/arm64
build darwin/amd64
build darwin/arm64
generate checksums
attach to GitHub Release
```

Do not publish Docker images in v1.

---

# 15. Comment check script

`script/check-comments.sh` should fail on ordinary comments.

Allowed:

```text
//go:
// Code generated
minimal doc comments for exported symbols
build tags
```

Suggested rough implementation:

```sh
#!/usr/bin/env bash
set -euo pipefail

bad=0

while IFS= read -r file; do
  while IFS= read -r line; do
    case "$line" in
      *"//go:"*) continue ;;
      *"Code generated"*) continue ;;
      *"// "*)
        echo "comment found: $file: $line"
        bad=1
        ;;
      *"/*"*)
        echo "block comment found: $file: $line"
        bad=1
        ;;
    esac
  done < "$file"
done < <(find . -name '*.go' -not -path './vendor/*')

exit "$bad"
```

The default posture should be no comments.

---

# 16. Acceptance checklist

The work is done only when all are true:

```text
[ ] kauket init creates a private GitHub repo when gh is authenticated.
[ ] kauket init falls back to GitHub device flow when gh is unavailable.
[ ] kauket add stores a real SSH private key in encrypted admin vault.
[ ] Git repo paths contain no secret names.
[ ] Git branch names contain no hostnames.
[ ] Git commit messages contain no secret names or hostnames.
[ ] kauket enroll creates age identity and deploy key.
[ ] kauket enroll submits encrypted request branch.
[ ] kauket approve shows pending request interactively.
[ ] kauket approve adds read-only deploy key.
[ ] kauket approve builds host bundle encrypted to host + admin.
[ ] kauket get syncs automatically.
[ ] kauket get installs ~/.ssh/main_private_key with 0600.
[ ] Existing unmanaged files are not overwritten silently.
[ ] Symlink destinations are refused.
[ ] Wrong host cannot decrypt another host's bundle.
[ ] Unapproved host cannot get secrets.
[ ] Metadata scan passes.
[ ] Local E2E passes.
[ ] GitHub E2E passes when explicitly enabled.
[ ] Amun install path works.
[ ] gofmt, go test, go test -race, go vet, staticcheck, govulncheck pass.
[ ] Code contains no nonessential comments.
```

---

# 17. Most important implementation warning

Do **not** accidentally rebuild the labeled secret tree we were trying to avoid.

This is wrong:

```text
secrets/ssh.main_private_key.age
bundles/r730xd-debian.age
requests/machine2-ssh.age
commit: approve machine2 ssh
deploy key title: machine2 r730xd ssh
```

This is right:

```text
admin/vault.age
bundles/h_7j4v6m2q9xk3p8da.age
request/rq_m5w8r0qf2p1x9z6a
requests/rq_m5w8r0qf2p1x9z6a.age
commit: kauket: approve request
deploy key title: kauket h_7j4v6m2q9xk3p8da
```

Kauket's whole security value over a naive SOPS/age repo is that the Git repository is an opaque transport, not a labeled map of your infrastructure.
