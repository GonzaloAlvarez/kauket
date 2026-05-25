# Kauket v1.0.0 — Acceptance Checklist

Spec reference: [`/specs/main-spec-v1.0.md`](../specs/main-spec-v1.0.md) §16.

| # | Acceptance criterion | Evidence | Status |
|---|---|---|---|
| 1 | `kauket init` creates a private GitHub repo when gh is authenticated | `internal/cli/init.go::ensureGitHubRepo` (Repositories.Create via go-github) + `e2e/github_test.go::TestGitHubInitEnrollApproveGet` (asserts `gh repo view --json private` is `true` after init) | Tested via gated GitHub E2E |
| 2 | `kauket init` falls back to GitHub device flow when gh is unavailable | `internal/githubauth/selector_test.go::TestSelectFallsThroughOnNotInstalled` + `internal/githubauth/device_test.go` (device flow happy path + scope handling); manual flow documented in `docs/oauth-app-setup.md` | Unit-tested; manual flow documented |
| 3 | `kauket add` stores a real SSH private key in encrypted admin vault | `e2e/real_data_test.go::TestRealDataSshEd25519PrivateKey` (real `ssh-keygen ed25519` key, round-trip through vault, `ssh-keygen -y` validates installed file) | Passing |
| 4 | Git repo paths contain no secret names | `internal/bundle/host_bundle_test.go::TestHostBundleCiphertextDoesNotLeakSecretNamesOrContent` + `scripts/leak-scan.sh` invoked from `scripts/e2e-local.sh` and `e2e/github_test.go::runLeakScan` | Passing |
| 5 | Git branch names contain no hostnames | `internal/gitstore/request_branch_test.go::TestRequestBranchNameLeakScan` (asserts `request/rq_[a-z2-7]{16}` shape only) + `e2e/enroll_local_test.go::TestEnrollLocalE2E` (asserts ref matches `^refs/heads/request/rq_[a-z2-7]{16}$`) | Passing |
| 6 | Git commit messages contain no secret names or hostnames | `internal/gitstore/store_test.go::TestGenericCommitMessageRoundTripNoLeakage` + `internal/gitstore/store_test.go::TestCommitAuthorMetadataLeakScan` (commit author neither leaks admin email nor OS hostname) | Passing |
| 7 | `kauket enroll` creates age identity and deploy key | `internal/cli/enroll_test.go::TestEnrollSuccess` (asserts `identities/host.txt`, `git/deploy_key`, `git/deploy_key.pub`, modes 0600/0644) | Passing |
| 8 | `kauket enroll` submits encrypted request branch | `e2e/enroll_local_test.go::TestEnrollLocalE2E` (pushes branch, asserts ref name, validates commit message + opaque author) + `internal/cli/enroll_test.go::TestEnrollRequestEncryptedToAdminRecipient` | Passing |
| 9 | `kauket approve` shows pending request interactively | `internal/cli/approve_test.go::TestApproveSingleRequest` (asserts spec §1.1 prompt format: `Pending requests:` block + `approve request 1? [y/N]`) | Passing |
| 10 | `kauket approve` adds read-only deploy key | `internal/gitstore/deploy_key_test.go::TestAddDeployKeyReadOnlyMandatory` (mocks GitHub API, asserts request body has `read_only: true`) + `e2e/github_test.go` end-to-end (asserts `read_only: true` via `gh api /repos/<slug>/keys` post-approve) | Tested via gated GitHub E2E |
| 11 | `kauket approve` builds host bundle encrypted to host + admin | `internal/cli/approve_test.go::TestApproveSingleRequest` (decrypts bundle with both host and admin identities) + `internal/bundle/host_bundle_test.go` | Passing |
| 12 | `kauket get` syncs automatically | `e2e/get_local_test.go::TestGetLocalE2E` (asserts `syncing store` line in output before install) + `internal/cli/get_test.go::TestGetCreatesFile` | Passing |
| 13 | `kauket get` installs ~/.ssh/main_private_key with 0600 | `e2e/get_local_test.go::TestGetLocalE2E` (asserts file mode 0600 and parent dir mode 0700; byte-identical to source; `ssh-keygen -y` round-trip) | Passing |
| 14 | Existing unmanaged files are not overwritten silently | `e2e/negative_test.go::TestNegativeExistingUnmanagedFile` + `internal/cli/get_test.go::TestGetUnmanagedDestinationFailsWithoutForce` + `TestGetUnmanagedDestinationWithBackup` | Passing |
| 15 | Symlink destinations are refused | `e2e/negative_test.go::TestNegativeSymlinkDestination` + `internal/cli/get_test.go::TestGetSymlinkRefused` (exit code 4, evil target untouched) | Passing |
| 16 | Wrong host cannot decrypt another host's bundle | `e2e/negative_test.go::TestNegativeWrongHostCannotDecryptBundle` (exit code 2, no destination written) | Passing |
| 17 | Unapproved host cannot get secrets | `e2e/negative_test.go::TestNegativeUnapprovedMachineCannotGetSecret` (exit code 5, message `no approved bundle found for this machine`) | Passing |
| 18 | Metadata scan passes | `scripts/leak-scan.sh` (wordlist matches spec §13.2) run from `scripts/e2e-local.sh` and `e2e/github_test.go::runLeakScan`; also asserted inside `e2e/get_local_test.go`, `e2e/real_data_test.go::TestRealDataSshEd25519PrivateKey`, and `TestRealDataAwsCredentialsFile` | Passing |
| 19 | Local E2E passes | `scripts/e2e-local.sh` (wired in `.github/workflows/ci.yml` step `e2e local`) + `go test ./e2e/... -tags=e2e` (init/enroll/approve/get/negative/real-data) | Passing |
| 20 | GitHub E2E passes when explicitly enabled | `e2e/github_test.go::TestGitHubInitEnrollApproveGet` (gated by `KAUKET_GITHUB_E2E=1`; build tag `github_e2e`; SSH portion skippable via `KAUKET_GITHUB_E2E_SKIP_SSH=1` for developer networks that block outbound port 22 per `docs/decisions/0001-ssh-transport.md`) | Pending CI / manual verification on unfiltered network |
| 21 | Amun install path works | DEFERRED — `amun-kauket` is out of scope for v1 (per locked decision; spec §8 captures the design for a follow-up release) | Deferred to v1.1 |
| 22 | gofmt, go test, go test -race, go vet, staticcheck, govulncheck pass | `.github/workflows/ci.yml` (matrix `ubuntu-latest`/`macos-latest`, runs all six tools in order) + `scripts/verify.sh` for local one-shot | Wired in CI |
| 23 | Code contains no nonessential comments | `scripts/check-comments.sh` (allowlists `//go:`, `Code generated`, `// +build`; rejects everything else) + CI step `check-comments` | Passing |

## Notes

- Item 20 (GitHub E2E) is the only criterion that requires a live GitHub repo and network access to `github.com:22`. The developer's local network filters outbound SSH per ADR 0001, so the SSH portion of this test must be exercised either in CI (GitHub Actions runners have no port-22 filtering) or on an unfiltered host. The test gracefully skips the SSH portion when `KAUKET_GITHUB_E2E_SKIP_SSH=1` while still exercising init → add → enroll → approve → deploy-key verification.
- Item 21 (Amun install path) is intentionally deferred. Spec §8 captures the desired `amun kauket` integration, and the binary's `cmd/kauket` build is artifact-ready via the goreleaser pipeline (`.goreleaser.yaml`) so the Amun role can fetch a release asset when it is implemented.
- "Tested via gated GitHub E2E" means the criterion has full coverage when `KAUKET_GITHUB_E2E=1` is set; unit-level coverage already validates the underlying primitives.
