#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== gofmt ==="
out=$(gofmt -l .)
if [ -n "$out" ]; then
  echo "$out"
  exit 1
fi

echo "=== go vet ==="
go vet ./...

echo "=== build ==="
go build ./...

echo "=== unit tests ==="
go test ./... -count=1

echo "=== unit tests -race ==="
go test ./... -race -count=1

echo "=== check-comments ==="
./scripts/check-comments.sh

if command -v staticcheck >/dev/null 2>&1; then
  echo "=== staticcheck ==="
  staticcheck ./...
else
  echo "staticcheck not installed; skipping (CI installs it)"
fi

if command -v govulncheck >/dev/null 2>&1; then
  echo "=== govulncheck ==="
  govulncheck ./...
else
  echo "govulncheck not installed; skipping (CI installs it)"
fi

echo "=== e2e-local ==="
./scripts/e2e-local.sh

echo "=== ALL GREEN ==="
