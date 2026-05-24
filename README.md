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

## Install

```sh
go install github.com/gonzaloalvarez/kauket/cmd/kauket@latest
```

GitHub Release binaries for linux/darwin × amd64/arm64 are attached to each tagged release.

## Spec

See [`specs/main-spec-v1.0.md`](specs/main-spec-v1.0.md) for the full v1.0 specification, including security goals, repository layout, encryption format, CLI surface, file-installation rules, verification plan, and acceptance checklist.

## License

GPL-3.0. See [`LICENSE`](LICENSE).
