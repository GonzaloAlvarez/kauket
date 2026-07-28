# Kauket v2.0 design study — per-namespace ACLs, owners vs readers, request/grant/revoke

Status: design study, accepted for planning 2026-07-28; execution plan approved the same day (phases 1–7, no interim phase 0, autonomous run-through on the v2 branch with three-layer per-phase verification including real-GitHub user journeys). Amendment A1 (§12) resolves a recipient-enumeration gap found during execution planning. On implementation this document supersedes spec v1.0 §§3–6 and interacts with ADRs 0001–0003 as noted in §9.

## 0. Motivation and reference systems

Kauket v1 is a single-admin, host-centric model: one admin identity holds the only key to the source of truth (`admin/vault.age`), grants are frozen at approve-time (replace-not-merge), there is no request/grant/revoke after enrollment, and clients verify nothing about what they install beyond "it decrypted". From the user's perspective the model is rigid: getting one more secret onto an already-enrolled machine requires re-enrollment.

The target model comes from two reference systems, studied in full:

- **peff/pass** (single GPG-encrypted YAML blob, `# recipient:` headers, dot-namespaced tree queries). Its own README names the motivating gap: *"you cannot use this pass to share subsets of your repository with another gpg key."* The namespace-tree ergonomics survive into v2; the single-blob recipient model does not.
- **kepr** (GonzaloAlvarez/kepr) — the target model, live: per-directory `.gpg.id` recipient lists, UUID-opaque directories with encrypted name metadata, `kepr request <path>` / `kepr request --approve` over ephemeral `access-request/*` git branches, grant = recursive decrypt/re-encrypt of the subtree (`pkg/store/rekey.go`).

kepr's structural weaknesses, all of which v2 fixes with machinery kauket already has:

| kepr weakness | v2 fix |
|---|---|
| Plaintext, unsigned `.gpg.id` ACLs — any pusher can self-append and poison future encryptions | ACLs live inside signed, encrypted manifests; forging a grant requires an owner's Ed25519 key |
| Every member holds a repo-write GitHub token; request-branch confinement is convention | Machines keep read-only deploy keys; one-shot interactive OAuth for requests; only owner-humans hold write |
| Non-atomic rekey — in-place per-file rewrite; crash leaves a mixed-recipient store | All mutations staged in the git working tree; exactly one commit per operation; `Sync` hard reset self-heals |
| No revoke command | `kauket revoke` with mandatory rotation guidance |
| UUID tree shape and per-directory fanout fully visible; plaintext member fingerprints | Flat opaque object store; membership encrypted |

kauket v1 strengths retained: direct age encryption with padded size classes (`internal/agebox`), Ed25519-signed requests with proof-of-possession (`internal/bundle/request.go`), read-only deploy keys (`internal/gitstore/deploy_key.go`, `ReadOnly: true`), atomic single-commit git operations with hard-reset crash recovery (`internal/gitstore/store.go`), and the whole install engine (`internal/install`), which is untouched by this design.

## 1. Target concept model

- **Identity** (`i_*`): `{kind: user|machine, age X25519 recipient, Ed25519 signing pubkey (SSH format), display name}`. Humans and machines are mechanically identical. Machines' steady-state read credential remains the read-only deploy key (ADR 0001 transport unchanged); their Ed25519 key signs only requests. Humans sign requests and manifests; human writes go through their own GitHub auth.
- **Namespace node** (`n_*`): a folder in the logical tree (`neptune/`, `aws/profile/`). Materialized as two objects: a **routing manifest** — signed body carrying `{schema, store_id, node_id, version (monotonic), updated_at, name, parent_id, children:[{node_id, owner_sign_keys[]}], owners:[{i_id, age_recipient, sign_pubkey}], index_object_id, index_sha256, prev_manifest_sha256, signature}` — and a **content index** (key names → secret object entries, reader ACL), integrity-bound by the manifest's `index_sha256` so it needs no second signature.
- **ACL per node**: `owners[]` (may sign the node's manifest: grant, revoke, add, rotate) and `readers[]` (may decrypt the index and secret objects). Owners are implicitly readers — granting requires re-encrypting, and re-encrypting requires reading. Per-key grants use per-entry reader lists on index entries (object recipients = node readers ∪ entry readers), avoiding forced tree restructuring.
- **Secret object** (`o_*`): one encrypted, padded blob per secret carrying `{kind, install spec, content, sha256}` — the fields of v1 `model.Secret` minus grants. Authenticated by the sha256 recorded in the signed chain, not by its own signature.
- **Recovery set** (default-on): an offline age + Ed25519 pair. The age recipient is appended to every object — preserving v1's "admin can always recover" guarantee and enabling rescue of orphaned nodes. The signing pubkey is a trust anchor, so rescue-signed manifests verify. It is a read-everything key: offline custody is mandatory; `--no-recovery` is permitted per store with loud orphan-risk warnings.
- **Store root**: the root node id, trust-anchor signing pubkeys, and recovery pubkeys are pinned in plaintext `store.json` (with a detached signature for rotation continuity), TOFU-pinned by every client at enrollment — exactly today's posture toward `repo.json.admin_recipients`.

### 1.1 Does "admin" survive? No — it dissolves.

Nothing in v2 requires a role that can read every secret. Every v1 admin function maps to something narrower:

| v1 admin function | v2 home |
|---|---|
| Only key that decrypts the source of truth (`admin/vault.age`) | Gone — no vault; truth is the signed manifest tree, held per-node by its owners |
| `kauket add`, grants at approve, bundle rebuilds | **Node owners**, per node |
| Approve enrollment; receive requests | **Root owners** — they can decrypt every routing manifest (structure + owner ACLs, for routing and audit) but not content indexes or secret objects outside their own grants |
| Recovery recipient on every bundle | **Recovery custodian** — offline keys, default-on, declinable |
| Deploy keys, repo creation, collaborator invites | **GitHub repo admin** — a platform role with zero decryption ability |

The result is exactly owner-of-key vs allowed-to-access-key. Residual store-level plumbing (root governance, recovery custody, GitHub administration) exists, and in a homelab it all lands on the same human: v2 degrades gracefully to v1's single-person UX while never *forcing* one key to read everything.

## 2. Store layout v2

```
kauket-store/                        (main branch)
  store.json                         plaintext: {schema: 2, store_id, format ids, github owner/repo,
                                     root_node_id, trust_anchors: [{i_id, sign_pubkey}],
                                     recovery: [{age_recipient, sign_pubkey}]}
  store.json.sig                     detached Ed25519 signature by a current trust anchor
  identities/
    i_p4k9....json                   plaintext keys only: {id, age_recipient, ssh_ed25519_pubkey}
                                     (no display names, no kinds — those live encrypted)
  objects/                           flat — no visible tree shape
    n_....age                        routing manifests (encrypted, padded, signed inside)
    x_....age                        content indexes (encrypted, padded, bound by manifest hash)
    o_....age                        secret objects (encrypted, padded, bound by index hash)
    r_....age                        routed requests (encrypted to a node's owners)
  request/rq_* branches              unchanged v1 transport (gitstore.PushRequest / FetchRequestRefs)
```

Leakage comparison for a repo-read attacker:

| Observable | kauket v1 | kepr | kauket v2 |
|---|---|---|---|
| Secret names / paths / hostnames | none | none, but tree shape + fanout fully visible | none; flat store hides shape |
| ACL membership | admin recipients in repo.json | full plaintext `.gpg.id` per directory | anchor + recovery pubkeys in store.json; per-identity pubkeys in identities/; *which identity reads which node* is encrypted |
| Number of secrets | # bundles ≈ # hosts; per-host counts hidden | exact count per directory | total object count (padded sizes only) |
| Grouping | weak (vault + affected bundles per change) | fully plaintext | **change-pattern correlation**: a grant commit rewrites a subtree's objects together, revealing that those k objects are related — the one concrete metadata regression vs v1; accepted and documented |
| Reader-set size per object | host+admin stanza count per bundle | n/a | age stanza count ≈ per-node reader count |

## 3. Integrity and trust chain

The fix for kepr's unsigned ACLs, built from kauket's existing signing machinery:

1. **Anchoring**: clients pin `store_id` + `trust_anchors` at enrollment. Updates to `store.json` must verify against the *previously pinned* anchor set (rotation continuity).
2. **Manifest signing**: manifests are canonical-JSON bodies (`model.MarshalCanonical`) signed Ed25519 — the exact `bundle.EncodeRequest`/`DecodeRequest`/`Ed25519Verifier` pattern lifted from requests to manifests.
3. **Chain**: root manifest signed by an anchor → each parent manifest attests `{child node_id, owner_sign_keys}` → a child manifest is trusted iff signed by a key in its parent's attestation. Index bound by `index_sha256`; each object by the sha256 in the index; `get` verifies the decrypted plaintext hash before install. v1 verified none of this.
4. **Recipient rules**: routing manifest of N decrypts to owners(N) ∪ readers(N) ∪ members of all descendants (so any grantee can walk its spine from the root) ∪ owners of all ancestors (governance down-view) ∪ recovery. Content index and secret objects of N: node members ∪ recovery only. Root owners never see key names or content they were not granted.
5. **What a push-capable non-owner can and cannot do**:
   - Cannot forge a grant (needs an owner signing key) — the headline fix over kepr.
   - Can replay an older signed state (rollback). Mitigated by monotonic `version` + `prev_manifest_sha256` + client-side version pinning; fresh clones remain exposed. Honest, unsolved in full.
   - Can re-encrypt an object they can already read to a wider recipient set (signature covers plaintext, not the age envelope). Not an escalation — such an actor could exfiltrate plaintext directly; an audit-hygiene gap only.
   - Can DoS (corrupt/delete/force-push) — detectable via signature/hash failure; machines cannot push at all.
   - Can withhold new commits (freshness) — unsolved, same as v1; optional signed heartbeat is roadmap phase 7.
6. **Client verification checklist** before trusting any manifest: store_id matches pin → signature chain to pinned anchors → version ≥ locally pinned version for that node → index/object hashes match → on any failure, exit 2 and install nothing.
7. **Owner-set changes**: a new owner on node N requires a manifest for N signed by an existing owner of N *plus* an updated attestation in parent(N) signed by a parent owner — two-party when they differ, by design (parents govern children's governance). Anchor rotation: new `store.json` + sig verifiable against the currently pinned set; total anchor loss is recoverable via the recovery signing key.

## 4. CLI surface v2

New commands:

| Command | Actor | Effect |
|---|---|---|
| `kauket request <path> [--key <name>]` | any enrolled identity | Signed access request, encrypted to the owners of the deepest readable ancestor ∪ trust anchors, pushed via one-shot interactive OAuth (v1 enroll transport) |
| `kauket grant <identity> <path> [--key <name>] [--owner]` | owner of the node | ACL update in signed manifest/index + re-encryption of affected objects, one commit; works with or without a pending request |
| `kauket revoke <identity> <path> [--key <name>]` | owner | Mirror of grant; always prints: *git history still contains ciphertexts the revoked key can decrypt — if compromised, rotate: [list]* |
| `kauket join` | a person | Human enrollment (user identity) — the people counterpart of machine `enroll` |
| `kauket rescue <path> --recovery-identity <file>` | recovery custodian | Decrypt anything; sign a manifest appointing new owners for an orphaned node; an ordinary auditable commit |
| `kauket verify` | anyone | Full-store audit: signature chain, hashes, version monotonicity |
| `kauket inspect --as <identity>` | owner | Computed view of what an identity can read (replaces `get --as-host`) |
| `kauket migrate-store` | v1 admin | One-time v1→v2 conversion (§8) |

Changed commands: `enroll --request <path>` requests paths/keys instead of profiles; `approve` handles both identity enrollments and routed access requests; `add`/`get`/`list` take paths (v1 dotted ids map 1:1 — `aws.profile.amzn-wanfe` ≡ `aws/profile/amzn-wanfe`); `list` shows granted subtrees fully plus the spine skeleton (ancestor names, child counts) and nothing else. Unchanged: `sync`, `status`, `version`, local `migrate`.

Canonical workflows:

```sh
# The pain this design exists to fix — post-enrollment access, no re-enrollment:
requester$  kauket request aws/profile/amzn-wanfe
owner$      kauket approve                  # grant + re-encrypt, one commit
requester$  kauket get aws/profile/amzn-wanfe

# Proactive grant, delegation, offboarding:
owner$      kauket grant i_9d2e neptune/
owner$      kauket grant --owner i_77ab k8s/    # i_77ab now approves k8s/ requests independently
owner$      kauket revoke i_77ab k8s/           # + rotation list if compromised
```

## 5. Flows

All mutating flows are single-commit atomic: mutations are staged in the git working tree and pushed as exactly one commit; a crash before push self-heals because the next `Sync` hard-resets to `origin/main` (`internal/gitstore/store.go`). On non-fast-forward push (another owner won the race): resync, **recompute from intent** (the operation is "grant X on N", not a tree diff), retry — kepr's `Rekey` made atomic and convergent.

- **init**: founder user identity (age + Ed25519); recovery pair generated and printed once with move-this-offline instructions (never stored in `$KAUKET_HOME`); `store.json`(+sig), root manifest, single commit.
- **enroll (machine) / join (human)**: identity generated locally; signed request (`bundle.EncodeRequest` unchanged — proof-of-possession retained) encrypted to trust anchors; pushed to `request/rq_*` with one-shot interactive OAuth, token discarded. Approval: verify signature, out-of-band confirmation, then atomically: write identity record, register read-only deploy key / send collaborator invite (GitHub API first, mirroring v1 `approveOne` ordering so an API failure leaves the store untouched), apply the initial grant, one commit, delete the request branch. Owner-humans receive write collaborator invites; everyone else stays read-only.
- **request routing**: when only trust anchors can read a request and none of them owns the target, a root owner re-encrypts it to the target node's owners as `objects/r_*.age` (owners are readable from routing manifests). Two hops worst case; zero extra hops in a homelab. Alternatives evaluated and rejected: standing write tokens for all members (kepr's flaw), and issue/PR-comment transports (new plaintext-adjacent surface).
- **add**: resolve path along the owner's spine; auto-create missing intermediate nodes where the creator owns the parent (child ACL copies the parent — kepr's inheritance rule); write object + index update + re-signed manifest; one commit. Destination inference, secret-kind dispatch (`file`, `aws_profile` per ADR 0003) carry over unchanged.
- **get**: sync (deploy-key SSH transport unchanged) → walk spine from pinned root → verify chain → decrypt index → decrypt object → verify sha256 → dispatch to `internal/install`. v1 exit codes preserved (5 not-granted on resolution dead-end, 2 on integrity failure).
- **grant / revoke**: §4; ancestor manifests need recipient widening/shrinking only (no re-sign — the signature covers the plaintext body, not the age envelope).
- **rescue / ownership transfer**: §3.7 and §4.

Cost model: cost(grant/revoke on N) = Σ padded sizes under N in age decrypt+encrypt + one signature + ancestor recipient rewrites. At homelab scale (~50 secrets, ~10 nodes, ~12 identities) a worst-case root-level operation is a few MB of X25519 work — sub-second; the git push dominates.

What dropping bundles loses, and mitigations: single-blob-per-host downloads (irrelevant — clones always fetched all bundles); bundle-as-grant-attestation (replaced by *signed* ACLs, strictly stronger — v1 bundles were unsigned); `bundle_generation` (never verified by any v1 client — verified in code; per-node version pinning is strictly stronger); per-host secret-count opacity (real regression, folded into the change-correlation caveat, accepted).

## 6. Security compromise analysis

Weaker than v1:
1. **Write-credential surface grows** — every owner-human holds a phishable GitHub credential with push. Forgery stays impossible; DoS/replay/laundering as bounded in §3.5.
2. **Change-pattern correlation** (§2) — the concrete metadata regression. Padding does not hide it; decoy traffic judged not worth the history growth (open decision D10).
3. **Authorization code complexity** — v1's grant logic is ~30 lines (`BuildHostBundle`); v2 adds chain verification, attestations, and recipient-set computation up and down the tree. Mitigations: recipient-set computation as a single pure exhaustively-tested function; `kauket verify` audit command.
4. **Rollback/freshness** only partially addressed (as v1, but richer semantics make replaying a pre-revocation state more attractive; version pinning narrows the window to fresh clones and long-offline clients).
5. **Revocation ≠ history erasure** — revoked keys decrypt historical ciphertexts forever (true in v1 and kepr too; v2 surfaces it in the UX with a mandatory rotation prompt).
6. **Trust anchors and recovery keys can forge/read everything** — equal to v1's admin, now explicit, offline, and declinable.

Stronger than v1:
1. **Per-node blast radius**: an owner-key compromise exposes one subtree; v1's admin key exposed every secret past and present. No key *must* read everything.
2. **Authenticity, finally**: signature chain + content hashes + version monotonicity, vs v1's decryptability-as-trust (a bundle-swap in v1 fails only by accident of decryption).
3. **Grant/revoke exist** as first-class, atomic, auditable operations; v1 grants were frozen at approve (replace-not-merge).
4. **Real multi-human ownership** without sharing an identity file (v1's `vault.Admins[]` is multi-recipient capable but has no add-admin flow — verified).
5. All five kepr structural flaws fixed (§0).

## 7. What can a partial reader see?

Within granted nodes: full key names and kinds. Along the spine to the root: ancestor node names and child *counts* (opaque ids). Nowhere else: nothing. Root owners additionally see the full namespace skeleton and per-node owner ACLs (routing/governance) but no key names or content outside their grants. Repo-read attackers see §2's table.

## 8. Migration and compatibility

- **Secrets**: dotted ids are already trees; fields copy verbatim into secret objects; `aws_profile` kind unchanged.
- **Profiles** (flat labels `ssh`, `host.kaiser`, `role.k8s_admin`): **materialized** into per-node reader grants at migration using v1 `affectedHosts` logic, with a printed mapping report. The abstraction is dropped; grant-set sugar can return client-side later.
- **Hosts**: become machine identities **reusing their existing age identities and deploy keys — zero client-side re-enrollment**. SSH pubkeys recovered from the GitHub deploy-key API (`DeployKeyManager.List`, matched by `kauket h_*` titles); file-remote stores fall back to fingerprint-only records.
- **Admin**: v1 admin age key → root-owner identity (a new Ed25519 signing key is generated — v1 admins have none). A fresh offline recovery pair is generated; the old admin age recipient stays in the recovery set through the transition so the v1 recovery guarantee never lapses, removable later by a full-store re-encrypt.
- **Bundles dropped ⇒ kauket v2.0.0 (major)**. Old clients on a migrated store fail *safely*: `get` finds no `bundles/<h_id>.age` and exits 5 ("no approved bundle found") — no corruption, a clear upgrade signal.
- **Strategy: in-place, big-bang, with a frozen-v1 window.** `migrate-store` writes the full v2 tree in one commit and leaves the final vault+bundles in place, frozen (`"frozen_v1": true`), so un-upgraded clients keep reading stale-but-valid bundles during the upgrade window; `--purge-v1` deletes them later. Dual-format *write* windows are rejected: the two authorization models diverge (per-node vs profile), so dual-write means resolving every operation twice under two models — the complexity that kills migrations. Honest caveat: the v1 vault ciphertext remains in git history, decryptable by the old admin key forever; a `--new-repo` flag offers a clean history at the cost of re-registering every deploy key and repointing every client.
- **`migrate-store` sequence**: lock → sync → decrypt vault → build node tree from dotted ids → create identities (hosts + admin) → materialize profile grants → generate recovery pair (interactive) → write store.json(+sig)/identities/objects → freeze v1 files → verification pass (simulate every migrated identity's read set; diff every secret sha256 against the vault) → single commit → report. Idempotent via schema-2 detection.
- **The dual-role home (ADR 0002) collapses** — stated plainly: "admin vs client" stops being a local role and becomes data ("do you own anything?"). Config v3 = one home with an *identity list*; a dual-role machine genuinely holds two identities (one human, one machine), so the two role homes map to two identity entries. ADR 0002's legacy-layout-forever read guarantee is honored; local `kauket migrate` grows one more converging step.
- **Untouched**: `internal/install`, `internal/awsconfig`, `internal/githubauth`, `internal/ui`, ADR 0001 (SSH transport), ADR 0003 (aws_profile). **New docs on implementation**: spec v2.0, ADR 0004 (identity homes), ADR 0005 (manifest trust chain), ADR 0006 (migration strategy).

## 9. Reused v1 machinery (verified against HEAD)

- `internal/model/canonical.go` `MarshalCanonical` — signed-body serialization for manifests.
- `internal/bundle/request.go` + `signer.go` — the sign-canonical-body-then-encrypt pattern and `Ed25519Verifier`, lifted from requests to manifests.
- `internal/agebox` — multi-recipient encryption (`combinedRecipientProvider` generalizes to reader∪owner∪recovery sets) and padding classes (a 4K class is proposed for manifests/indexes).
- `internal/gitstore` — `Sync` hard reset (crash recovery), `CommitAndPush` (single-commit atomicity), `ErrNonFastForward` retry contract, `PushRequest`/`FetchRequestRefs` (request transport unchanged), `DeployKeyManager` (read-only keys + `List` for migration).
- `internal/cli/approve.go` `approveOne` — GitHub-API-before-commit atomic approve ordering; `internal/cli/add.go` `affectedHosts` — profile materialization during migration and the Phase 0 interim commands.
- `internal/model/ids.go` — id generation for the new `n_`, `x_`, `o_`, `r_`, `i_` prefixes.

## 10. Phased roadmap (each phase independently shippable; 1–2 ship dark)

| Phase | Content | Size |
|---|---|---|
| 0 | **Interim `grant`/`revoke` in the v1 model**: vault edit + bundle rebuild via existing `affectedHosts`/`BuildHostBundle`; fixes approve's replace-not-merge. Ships the missing capability in days and locks in the v2 UX (names, flags, messages, exit codes); roughly half the internals are throwaway. Recommended: include. | S |
| 1 | `internal/manifest` foundations: types, signed canonical bodies, the pure recipient-set function, new id prefixes, optional 4K padding class | M |
| 2 | v2 read path (walk/verify/pin) + `migrate-store` with verification pass + frozen-v1 window | L |
| 3 | Owner write paths: v2 `add`, `grant`, `revoke`, atomic rekey with recompute-retry | L |
| 4 | Requests v2: path/key requests, deepest-ancestor targeting, routing, `approve` v2, human `join` | M |
| 5 | Multi-owner governance: `grant --owner`, parent attestations, transfer, anchor rotation, identity-home config v3 (ADR 0004) | M |
| 6 | `rescue`, recovery-set add/remove, `verify` audit, `inspect --as <i_id>` | M |
| 7 | Optional freshness heartbeat, e2e suites, spec v2.0 + ADRs, `--purge-v1`, release v2.0.0 | S/M |

## 11. Open decisions (defaults chosen; each vetoable before its phase lands)

| # | Decision | Default | Consequence of the alternative |
|---|---|---|---|
| D1 | ACL representation | Signed + encrypted manifests, flat store | kepr-style plaintext `.gpg.id`: simpler, but leaks tree+membership and reintroduces unsigned-ACL forgery — defeats the premise |
| D2 | Identity model | Unified human/machine | Separate types = today's `AdminInfo`/`HostInfo` drift, duplicated flows forever |
| D3 | Recovery | Default-on, offline, on every object | `--no-recovery`: no read-everything key exists, but nodes whose owner keys are lost are cryptographically unrescuable |
| D4 | Owner-set verification | Parent attestation + client continuity pinning (both) | Attestation-only loses rollback detection for cached clients; history-only makes fresh clones walk git history |
| D5 | Request transport | One-shot interactive OAuth push (v1's) | Standing write tokens = kepr's central flaw; acceptable later as owner-human convenience only |
| D6 | Identity records | Plaintext keys only; names/kinds encrypted | Fully encrypted identities require an all-members recipient set re-encrypted on every join, for marginal gain |
| D7 | Profile migration | Materialize into per-node grants + report | First-class label objects create cross-tree ACL indirection the signed-manifest model cannot authenticate per-node |
| D8 | Migration repo | In-place with frozen-v1 window; `--new-repo` optional | Fresh repo cleans history (old vault ciphertext gone) but re-registers every deploy key and repoints every client |
| D9 | Padding | Add a 4K class for manifests/indexes | 16K minimum triples store/history growth for tiny metadata; cost is one more observable bucket |
| D10 | Change-correlation leakage | Accept + document; optional `--batch` coalescing | Decoy re-encryption inflates history and recovery complexity for a weak adversary win |
| D11 | Machine owners | Allowed, warned (`grant --owner` to a machine identity prompts) | Hard prohibition special-cases identity kinds everywhere and blocks legitimate automation stores |
| D12 | Phase 0 | Include | Skipping saves ~a week now and leaves the grant-after-approve gap open for the entire v2 build. **Execution decision 2026-07-28: skipped by user choice** — all effort goes directly to v2 |

## 12. Amendment A1 — recipient enumeration and the envelope cache (2026-07-28)

Section 3.4's recipient rule as originally written has an enumeration gap discovered during execution planning: the writer of manifest(N) cannot enumerate the members of sibling subtrees (their reader ACLs live in indexes it cannot decrypt), and a grantor at a deep node cannot recompute ancestor manifests' recipient sets from scratch. Resolution, consistent with §3.5's concession that envelope recipients are unauthenticated:

1. Each node's reader ACL of record — `readers[]` plus a name-free `extra_readers[]` (the deduplicated union of the node's per-entry reader lists) — lives in the **signed manifest body**. Any owner of N can decrypt every descendant manifest (ancestor-owner rule) and therefore compute exact recipient sets for anything it signs. Key names never appear in manifests, preserving §7.
2. The encrypted manifest **file** is an envelope `{"body": …, "recipients": […]}` where `recipients` is an unsigned cache of the current envelope recipient set. A grantor at node D widens each ancestor manifest's envelope by re-encrypting to `cache ∪ {new recipient}` without needing to enumerate sibling membership and without re-signing (the signature covers the body, not the envelope).
3. Revoke shrinks the envelopes of everything under the revoked node plus any ancestor manifests the acting owner owns; other ancestors' caches are conservatively left wide. The residue is spine metadata only — never content indexes or secret objects — and is reported by `kauket verify` (cache-drift check) and repaired on the next owner rewrite of the affected node.
