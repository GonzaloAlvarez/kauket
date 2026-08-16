#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: preflight-store.sh <KAUKET_HOME> [kauket-binary]" >&2
  echo "  Read-only pre-rollout check for an existing store: verifies the signature" >&2
  echo "  chain/hashes and pre-flights every readable secret's install target against" >&2
  echo "  the new binary's install policy. Run against a COPY of a production store." >&2
  echo "  Note: verify auto-syncs first and falls back to the local copy if the" >&2
  echo "  remote is unreachable; against a copy the fetch/reset is harmless." >&2
  exit 2
fi

HOME_DIR="$1"
KAUKET="${2:-kauket}"

echo "=== kauket verify (signatures, hashes, version pins) ==="
KAUKET_HOME="$HOME_DIR" "$KAUKET" verify

echo "=== kauket verify --installs (confinement, mode, aws directive pre-flight) ==="
KAUKET_HOME="$HOME_DIR" "$KAUKET" verify --installs

echo "=== kauket status (schema + trust-anchor fingerprint) ==="
KAUKET_HOME="$HOME_DIR" "$KAUKET" status

echo "=== ALL GREEN: store is safe to read with this kauket version ==="
