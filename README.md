# kauket

Direct-age, Git-backed, per-host secret bundle manager.

## What it is

kauket is a Go CLI that distributes per-host secret bundles via a private GitHub repository. The root of trust stays on a single admin machine (or, in a later version, a YubiKey). Each enrolled machine receives an opaque encrypted bundle containing only the secrets it has been granted, and unwraps that bundle locally onto the filesystem with the correct permissions.

The on-disk Git layout is intentionally opaque: no hostnames, no secret names, no destination paths, no profile names ever appear in plaintext inside the repository, branch names, commit messages, or deploy-key titles.

Encryption is direct [`filippo.io/age`](https://github.com/FiloSottile/age) — no SOPS, no GPG, no server-side secrets service. The Git repository is a transport, not a labeled map of your infrastructure.

## Quick start

```sh
# Admin machine
kauket init
kauket add ssh.main_private_key ~/.ssh/main_private_key.pem

# New machine
kauket enroll --request ssh

# Admin machine
kauket approve

# New machine
kauket get ssh.main_private_key
```

AWS profiles can be captured and distributed without touching other profiles on the target machine:

```sh
# Admin machine: capture [profile amzn-wanfe] (and its sso-session) from ~/.aws
kauket add --aws-profile amzn-wanfe

# Client machine: merge just that profile into ~/.aws/config and ~/.aws/credentials
kauket get aws.profile.amzn-wanfe
```

## Running admin and client on the same machine

A machine can hold both roles in one `KAUKET_HOME` (default `~/.config/kauket`). Each role lives in its own subdirectory, and every command picks the role it needs — no environment switching:

```sh
kauket init                 # creates <KAUKET_HOME>/admin/
kauket enroll --request ssh # creates <KAUKET_HOME>/client/ alongside
kauket add ...              # admin commands use admin/
kauket get ...              # client commands use client/
kauket status               # shows both roles; --role admin|client narrows
```

Pre-existing installs that keep `config.json` at the `KAUKET_HOME` root continue to work unchanged. To normalize one into the role-subdirectory layout, run `kauket migrate`.

To consolidate two existing single-role homes into one:

```sh
KAUKET_HOME=~/.config/kauket kauket migrate   # move the default home's role into its subdir
mv $OLD_CLIENT_HOME ~/.config/kauket/client   # bring the other role in as client/ (or admin/)
kauket status                                 # shows both roles
```

All paths stored in a role's config are relative, so a role home is relocatable as a unit.

## Namespace stores (v2)

v2 replaces the single admin vault and per-host bundles with a tree of namespace nodes, each with its own owners and readers. There is no admin role: whoever owns a node grants, revokes, and delegates access to it. Identities (people or machines) request access at any time; owners approve. Every node manifest is signed, so a repo writer cannot forge a grant, and clients verify the signature chain and content hashes before installing.

```sh
kauket init --v2 --recovery-out ~/kauket-recovery   # found a namespace store (move recovery keys offline)
kauket add aws.profile.amzn-wanfe ...               # dotted ids are namespace paths
kauket enroll --request aws/profile                 # a machine requests a namespace path
kauket approve                                       # owner approves; grants the requested path
kauket request infra/k8s                             # an enrolled identity asks for more, any time
kauket grant  i_9d2e neptune/                        # owner grants proactively
kauket grant  --owner i_77ab k8s/                    # delegate ownership of a subtree
kauket revoke i_77ab k8s/                            # revoke (prints a rotation list)
kauket rescue neptune/ --recovery-identity ... --recovery-sign-key ... --new-owner i_x
kauket verify                                        # audit the chain and hashes
kauket inspect --as i_9d2e                           # what can this identity read?
```

Migrate an existing v1 store in place with `kauket migrate-store --recovery-out <dir>`: dotted ids become the tree, per-host grants are materialized exactly, hosts keep their identities and deploy keys (no re-enrollment), and the v1 vault/bundles stay frozen for un-upgraded clients until `kauket migrate-store --purge-v1`. See [`specs/design-v2.0-namespace-acl.md`](specs/design-v2.0-namespace-acl.md) and ADRs 0004–0006.

## Install

Via [amun](https://github.com/GonzaloAlvarez/amun) (recommended; verifies checksum, installs binary, creates `~/.config/kauket` with mode 0700):

```sh
amun kauket
```

Via `go install`:

```sh
go install github.com/gonzaloalvarez/kauket/cmd/kauket@latest
```

GitHub Release binaries for linux/darwin × amd64/arm64 are attached to each tagged release at <https://github.com/GonzaloAlvarez/kauket/releases>.

## Spec

See [`specs/main-spec-v1.0.md`](specs/main-spec-v1.0.md) for the full v1.0 specification, including security goals, repository layout, encryption format, CLI surface, file-installation rules, verification plan, and acceptance checklist.

## License

GPL-3.0. See [`LICENSE`](LICENSE).
