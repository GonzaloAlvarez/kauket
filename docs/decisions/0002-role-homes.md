# ADR 0002 — Role-aware dual config (admin/ and client/ role homes)

## Status

Accepted. 2026-07-27. Supersedes spec §5 of `specs/main-spec-v1.0.md` (lines mandating that `kauket init` on a client machine must fail, and the implied one-role-per-`KAUKET_HOME` model).

## Context

A `KAUKET_HOME` previously held exactly one `config.json` whose `role` field made the machine either admin or client, and `init`/`enroll` rejected the opposite role. A machine acting as both the admin and an enrolled client needed two separate config directories and constant `KAUKET_HOME` switching.

Prior art (kubectl contexts, AWS CLI profiles, gcloud configurations, `gh auth switch`) solves "N configs, one binary" with named profiles plus a sticky current-context switch. kauket's need is narrower: exactly two roles, and nearly every command already implies its role (`init`/`add`/`approve` are admin-only; `enroll`/`get` are client operations; `get --inspect`/`--as-host` are admin). A context switch would still require switching; role-based auto-selection requires none.

The term "profile" was deliberately avoided — the vault already uses it for secret grouping.

## Decision

Both roles coexist under one `KAUKET_HOME`, each in a fully self-contained role home:

```
$KAUKET_HOME/
  admin/    config.json, identities/admin.txt, repo/, repo.lock
  client/   config.json, identities/host.txt, git/deploy_key, repo/, state/, repo.lock
```

- `config.ResolveRoleHome(base, role)` resolves a role's home with precedence: canonical `base/<role>/` subdirectory, then `base` itself (legacy layout), else not-found with the canonical path as creation target. A subdirectory config declaring the wrong role is a hard error.
- Every command resolves the role it needs: `init` creates/uses `admin/`, `enroll` creates/uses `client/`, `add`/`approve` require admin, `get` requires client (admin for `--inspect`/`--as-host`). `sync`/`status`/`list` operate on all installed roles and accept `--role admin|client` to narrow.
- Per-role `repo/` clones are intentional: the admin syncs over HTTPS token auth while the client uses its SSH deploy key, and separate `repo.lock` files let the roles operate concurrently.
- **Back-compat is a permanent guarantee, not a migration window**: legacy root-layout homes are read transparently forever. Upgrading the binary never moves or rewrites user data.
- `kauket migrate` optionally normalizes a legacy root layout into the role subdirectory. It moves `identities/`, `git/`, `state/`, `repo/`, and `config.json` — config last, so an interrupted migration leaves the root authoritative and re-running converges.

## Consequences

- `kauket init` on a client machine now succeeds and creates the admin role alongside — superseding the spec's refusal requirement. Enrollment on an admin machine likewise creates the client role alongside.
- Single-role machines behave byte-identically (including `synced` output and exit codes); dual-role machines get `synced admin` / `synced client` and multi-section `status`/`list` output.
- `config.RequireRole`/`WrongRoleError` were removed; role checks happen at home resolution with hint-bearing errors (e.g. "run 'kauket enroll' to add it").
