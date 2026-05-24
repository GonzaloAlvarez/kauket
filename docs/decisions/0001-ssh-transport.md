# ADR 0001 — SSH transport for post-approval client sync

## Status

Accepted. 2026-05-24.

## Context

Post-approval clients sync the store using a per-host SSH deploy key registered on the GitHub repo (read-only, `read_only=true`). GitHub's deploy-key feature is SSH-only — there is no HTTPS equivalent. The kauket CLI must therefore speak SSH to `git@github.com` using an in-memory or on-disk Ed25519 private key, with the server's host key validated against a pinned set of known-hosts entries.

Two implementation paths were considered:

1. **`go-git/v5` with `plumbing/transport/ssh`** — pure-Go, no shell-out, no `git` binary required at runtime.
2. **System `git` behind an `os/exec` wrapper** — shell out to `git -c core.sshCommand="ssh -i <key> -o UserKnownHostsFile=<pinned> -o IdentitiesOnly=yes"` for clone/fetch/push.

A throwaway spike was run in `/tmp/kauket-ssh-spike/` against `go-git/v5 v5.19.1` and `golang.org/x/crypto/ssh/knownhosts` v0.52.0, using the developer's existing `~/.ssh/id_ed25519` and the system `~/.ssh/known_hosts` file, attempting to clone the public `git@github.com:GonzaloAlvarez/kauket.git` repository.

Findings:

- `transport/ssh.PublicKeys{User: "git", Signer: signer}` accepts a `golang.org/x/crypto/ssh.Signer` (works equally well for keys parsed from disk and keys generated in memory via `ssh.NewSignerFromKey(ed25519.PrivateKey{…})`).
- `knownhosts.New(path)` produces a `ssh.HostKeyCallback` that is directly assignable to `auth.HostKeyCallback`. Comma-separated `host,ip` lines that `ssh-keyscan` does NOT emit but that I hand-typed were rejected with `ssh: short read`; using a real `known_hosts` file produced by `ssh-keyscan` or copy-paste from the existing one parses cleanly.
- `gogit.PlainClone(...).CloneOptions{Auth: auth}` proceeded all the way to an SSH handshake against GitHub.
- The handshake timed out at `read tcp ...:22: read: operation timed out`. Confirmed with `ssh -T git@github.com` and `nc -vz github.com 22` that the TCP handshake completes (port reachable) but the SSH banner exchange times out — this is a developer-network outbound-22 filtering issue, not a library limitation.

## Decision

**Primary**: implement `internal/gitstore.SSHDeployKeyTransport` using `go-git/v5/plumbing/transport/ssh` directly. Embed a small static known-hosts pin file with the current GitHub `ssh-ed25519`, `ssh-rsa`, and `ecdsa-sha2-nistp256` entries (rotation procedure documented in this ADR). Load the deploy key from `~/.config/kauket/git/deploy_key` (mode 0600) and convert to an `ssh.Signer` once at startup; never hold the raw bytes longer than necessary.

**Fallback (deferred past v1)**: a system-`git` transport that shells out with `GIT_SSH_COMMAND` configured was originally planned to back the same `Transport` interface and be selected when the in-process path was explicitly disabled via `KAUKET_GIT_TRANSPORT=system`. v1 ships **only** the in-process `SSHDeployKeyTransport`. The fallback is not implemented because the existing `Store` only consumes `transport.AuthMethod` (which the system-git path does not satisfy); a shell-out path would require a separate `Store` code path. We defer that work until field testing surfaces an environment where the in-process transport is genuinely unworkable. If it becomes necessary, this ADR will be superseded by a follow-up describing the dual-path design.

The single transport is constructed behind the existing `internal/gitstore.Transport` interface so future callers can swap implementations without touching `Store`. Tests in `internal/gitstore` cover the HTTPS, `file://`, and (offline) SSH selection paths; the SSH path is exercised end-to-end in `e2e/github_test.go` (gated by `KAUKET_GITHUB_E2E=1`), where real network conditions and real GitHub host keys are present.

## Known-hosts pin rotation

GitHub publishes its host keys at <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints>. The pinned file ships in `internal/gitstore/github_known_hosts.txt` (embedded via `//go:embed`). On rotation, regenerate via:

```sh
ssh-keyscan -t ed25519,rsa,ecdsa github.com > internal/gitstore/github_known_hosts.txt
```

…and verify the SHA-256 fingerprints against GitHub's published list before committing. A regression test asserts the file is non-empty, contains at least one `ed25519` line, and that all lines parse via `knownhosts.New`.

## Consequences

- v1 ships only the in-process SSH transport; `Transport` interface keeps the call sites clean and leaves room for the deferred system-`git` fallback.
- Adding `age-plugin-yubikey` later doesn't touch this code (signer becomes a plugin-backed `ssh.Signer`).
- Developers behind networks that filter outbound port 22 currently have no in-tool workaround. If this proves to bite in practice we revisit the deferred system-`git` fallback (which would use ssh-over-443 or any proxy configuration the user has already wired into their `~/.ssh/config`).
- The hard-coded known-hosts pin is a maintenance liability; the rotation procedure above keeps it manageable.
