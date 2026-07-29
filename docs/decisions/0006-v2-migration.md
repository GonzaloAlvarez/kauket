# ADR 0006 — v2 migration and recovery

## Status

Accepted. 2026-07-29. Implements §8 (migration) and §1 (recovery set) of `specs/design-v2.0-namespace-acl.md`.

## Context

Existing v1 stores hold a vault and per-host bundles; v2 needs those secrets and grants as a signed namespace tree, without losing data and without a flag day for un-upgraded clients. v2 also needs a recovery story now that no single online key reads everything.

## Decision

`kauket migrate-store` converts a v1 store in place. Dotted secret ids become the namespace tree (`aws.profile.amzn-wanfe` → node `aws/profile`, key `amzn-wanfe`); each `model.Secret`'s fields copy verbatim into a secret object (the `aws_profile` kind of ADR 0003 included). Per-host grants are materialized from the exact v1 oracle `bundle.BuildHostBundle`: a host that could read a secret in v1 becomes a node reader or a per-entry reader of the corresponding object in v2. Hosts keep their existing age identities and deploy keys as machine identities, so no client re-enrolls; host signing pubkeys are recovered from the GitHub deploy-key API.

A **self-verification pass** runs after staging and before the single commit: it re-verifies the signed `store.json`, decrypts every staged object from disk with the recovery key, walks the full tree as the founder, checks bidirectional per-host read-set equivalence against the v1 oracle (identical secret-id sets and byte-identical content/sha/install/kind), and confirms the frozen v1 files are byte-unchanged. Any failure hard-resets the worktree and pushes nothing.

The v1 vault and bundles are left in place, **frozen** (`frozen_v1: true` in `store.json`), so un-upgraded clients keep reading stale-but-valid bundles during the upgrade window; upgraded clients ignore them. `kauket migrate-store --purge-v1` later deletes them and clears the flag. Old clients on a migrated store fail safely (`get` finds no bundle, exits 5).

A **recovery key pair** (offline age + Ed25519) is generated at `init --v2`/`migrate-store` via `--recovery-out` and printed with a move-it-offline warning. Its age recipient is appended to every object (preserving v1's admin-recovery guarantee); its signing key is a store anchor. `kauket rescue` uses it to appoint a new owner for an orphaned node, and the migration keeps the old v1 admin recipient in the recovery set through the transition so the guarantee never lapses.

## Consequences

- Migration is idempotent (schema-2 detection) and never leaves a half-migrated store on the remote.
- Dropping bundles makes this a major version (v2.0.0); the frozen window plus safe-fail old clients make the cutover gradual rather than a flag day.
- Honest caveat: the v1 vault ciphertext remains in git history, decryptable by the old admin key, until history is rewritten or the repo is recreated; `--purge-v1` removes the working-tree copy but not history.
- The recovery key is a read-everything, sign-anything key; offline custody is mandatory, and `--no-recovery` (design D3) trades that away for unrescuable orphaned nodes.
