# ADR 0004 — v2 manifest trust chain

## Status

Accepted. 2026-07-29. Implements the trust model of `specs/design-v2.0-namespace-acl.md` (§3 and Amendment A1).

## Context

kauket v2 replaces the single admin vault and per-host bundles with a tree of per-namespace nodes. Access control moves into the store data itself, so the store data must be authenticated: a client (or a compromised repo writer) must not be able to forge a grant, and a client must be able to verify what it installs beyond "it decrypted", which was the whole of v1's client-side verification.

## Decision

Each namespace node is a **routing manifest** whose canonical-JSON body is Ed25519-signed, reusing `model.MarshalCanonical` and `bundle.Signer`/`Ed25519Verifier` unchanged — the same sign-canonical-body pattern v1 uses for enrollment requests. The manifest body carries the node's owner and reader ACLs (Amendment A1: reader ACLs of record live in the signed body, with a name-free `extra_readers` union of per-entry readers), the child attestations `{node_id, owner_sign_keys}`, and the `index_sha256` binding of the node's content index. The content index binds each secret object by sha256. Secret objects are verified against that sha256 before install.

Verification chains from a pinned root: the client pins `store_id` and the trust anchors at first contact (TOFU, exactly v1's posture toward `repo.json.admin_recipients`). `store.json` is a plaintext document with a detached Ed25519 signature; updates must verify against the previously pinned anchor set, giving rotation continuity. The root manifest must be signed by a trust anchor; each non-root manifest must be signed by a key in its parent's child attestation **or** by a recovery signing key (recovery keys are store-wide anchors, so a rescue-signed manifest verifies anywhere — see ADR 0006). Monotonic `version` plus client-side node-version pins detect rollback of an already-seen node.

The encrypted manifest file wraps the signed body in an envelope `{body, recipients}` where `recipients` is an unsigned cache of the current age recipient set. This lets a grant widen an ancestor manifest's envelope without re-signing it (the signature covers the body, not the envelope), which is what makes a deep grant a bounded operation. Recipient sets for every artifact are computed by one pure function (`manifest.RecipientSet`).

## Consequences

- A push-capable non-owner cannot forge a grant: ACL changes live in a signed body and require an owner key. This is the headline fix over kepr's plaintext, unsigned `.gpg.id` files.
- Clients verify a signature chain, content hashes, and version monotonicity before writing anything to disk (exit 2 on any failure).
- Residual, documented gaps carried from the design study: rollback is only fully prevented for already-seen nodes (fresh clones rely on the chain alone); freshness/withholding is unsolved; and an actor who can already decrypt an object can re-encrypt it to a wider set (not an escalation).
- Trust anchors and recovery keys can forge or read anything — the same ultimate power v1's admin key held, now explicit, and for recovery held offline.
