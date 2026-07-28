# ADR 0003 — AWS profile secrets (`aws_profile` kind with section-merge install)

## Status

Accepted. 2026-07-27.

## Context

Distributing an individual AWS profile through kauket previously meant hand-assembling a file secret, and installing it could only replace a whole file — clobbering every other profile in the client's `~/.aws/config` and `~/.aws/credentials`. Users keep multiple profiles in those files, so per-profile distribution needs surgical merging, not whole-file installs. This is kauket's first secret kind beyond `file`.

## Decision

`kauket add --aws-profile <name>` captures the profile's sections from the admin's `$AWS_CONFIG_FILE`/`~/.aws/config` and `$AWS_SHARED_CREDENTIALS_FILE`/`~/.aws/credentials` into vault secret `aws.profile.<name>` with `kind: "aws_profile"`. On the client, `kauket get aws.profile.<name>` merges those sections into the corresponding files, preserving everything else byte-for-byte.

Key choices:

1. **JSON envelope content (schema 1)**: `{"schema":1,"profile":...,"config":...,"credentials":...}` where `config`/`credentials` hold raw INI text of the captured sections. Extensible without changing the vault/bundle schema; `--stdout`/`--inspect`/`--as-host` print it raw.
2. **Empty `install` spec as the old-client failure mode**: pre-v1.3 clients ignore `kind` and would install the envelope verbatim at `install.destination`. With an empty destination, `install.InstallFile` fails with `install: empty destination` (exit 4, zero writes) instead of corrupting `~/.aws` files. Deliberate and verified.
3. **Line-based section splitter, no INI dependency**: sections are recognized by column-0 `[...]` header lines; everything else is opaque bytes. A parse→render round trip is byte-identical, which is what guarantees untouched profiles, comments, and formatting survive merges. A full INI parser would normalize formatting and add a dependency for no benefit.
4. **Secret-id charset relaxed to allow hyphens inside segments** (`^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$`): AWS profile names commonly contain hyphens (`amzn-wanfe`). Backward-compatible superset; secret ids never appear in file names, branch names, or leak-scan wordlists. AWS profile names that still cannot be encoded (uppercase, dots, leading hyphen) are rejected at `add` with a clear error.
5. **`sso_session` references are followed** — the matching `[sso-session X]` config section is captured and merged too, since an SSO profile is unusable without it. `source_profile` references only warn: recursive profile capture is out of scope; add the referenced profile separately.
6. **Section-level managed state**: `installed.json` entries gain an optional `sections` map (`config|<key>` / `credentials|<key>` → sha256 of the normalized section). Replacing a differing section kauket did not install requires `--force` or `--backup` (whole-file backup), mirroring the whole-file unmanaged rule at section granularity. Rotation via re-`add --force` + re-`get` needs no flags on the client.
7. **Two-phase merge**: both target files are planned before either is written, so a conflict in one file leaves both untouched.
8. **Equivalences and limits**: `[profile X]` ≡ `[X]` and `[default]` ≡ `[profile default]` in config files; matching is case-sensitive; CRLF content is preserved but not converted (an LF-captured section vs a CRLF local section compares as different and follows the unmanaged rule); duplicate same-name sections in a target collapse to one on merge.

## Consequences

- The client `get` path dispatches on `kind`; unknown kinds fail with `unsupported kind ...; upgrade kauket` rather than misinstalling.
- Existing file secrets, their state entries, and single-kind bundles are unchanged; legacy `installed.json` files load as-is.
- Spec §§4.3, 6.3, 6.6, 7.4 amended and §7.5 added; secret-id validation section updated for the relaxed charset.
