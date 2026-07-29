# ADR 0005 — v2 unified identities and local config

## Status

Accepted. 2026-07-29. Implements §1 (identity model) and the migration/config notes of `specs/design-v2.0-namespace-acl.md`.

## Context

v1 had two disjoint local identities — an admin (age key only) and a host (age key + read-only deploy key) — and the "admin vs client" split had just been made a local role by ADR 0002. v2 dissolves the admin role into per-node owners, so a local home is no longer "an admin" or "a client"; it holds an identity that may own some nodes and read others.

## Decision

An identity is `{id, kind: user|machine, age recipient, Ed25519 signing pubkey, display name}`, recorded in the store under `identities/<id>.json` with keys only (no names or kinds in plaintext, per design decision D6). Humans and machines are mechanically identical; machines keep the read-only deploy key as their steady-state read credential and use a one-shot interactive OAuth push for requests, while humans push with their own GitHub auth when they own nodes. `kauket enroll` creates a machine identity, `kauket join` a human one; both send a signed request that `kauket approve` verifies (refusing to rebind an existing id to a different age recipient) and grants through the same engine as `kauket grant`.

Rather than a disruptive config rewrite, the existing per-role `config.json` gained an optional `v2` block `{identity_id, sign_key_path}` (omitempty), so v1 layouts are untouched and a v2 home records its signing identity in place. Client pin state lives at `state/pins.json` in the role home. The v1 dual-role home layout (ADR 0002) and its legacy-read guarantee are preserved; a machine that is both a human owner and an enrolled client simply keeps two homes/identities, which is now a first-class situation rather than a special case.

## Consequences

- One identity concept spans people and machines; ownership follows identities, not the admin/client label.
- v1 configs load unchanged; the `v2` block is additive and ignored by v1 code paths.
- Trust anchors in `store.json` carry age recipients (matching v1's exposure of admin recipients in `repo.json`), so requests can always be encrypted to a reachable owner.
- A standalone identity-list config and a `rotate` command were deferred; anchor rotation is handled through the `store.json` re-sign path exercised by root-owner grant/revoke.
