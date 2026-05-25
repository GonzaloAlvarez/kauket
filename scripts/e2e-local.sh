#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT

REMOTE="$ROOT/kauket-store.git"
ADMIN_HOME="$ROOT/admin-home"
MACHINE_HOME="$ROOT/machine2-home"

mkdir -p "$ADMIN_HOME" "$MACHINE_HOME"
git init --bare -b main "$REMOTE" >/dev/null

go build -o "$ROOT/kauket" ./cmd/kauket

echo "=== init admin ==="
KAUKET_HOME="$ADMIN_HOME/.config/kauket" HOME="$ADMIN_HOME" "$ROOT/kauket" init --remote "file://$REMOTE" --no-github --yes

echo "=== generate + add ssh key ==="
mkdir -p "$ADMIN_HOME/.ssh"
ssh-keygen -t ed25519 -N "" -f "$ADMIN_HOME/.ssh/main_private_key.pem" -q
KAUKET_HOME="$ADMIN_HOME/.config/kauket" HOME="$ADMIN_HOME" "$ROOT/kauket" add ssh.main_private_key "$ADMIN_HOME/.ssh/main_private_key.pem"

echo "=== enroll client ==="
KAUKET_HOME="$MACHINE_HOME/.config/kauket" HOME="$MACHINE_HOME" "$ROOT/kauket" enroll --remote "file://$REMOTE" --request ssh --name machine2 --yes

echo "=== approve ==="
KAUKET_HOME="$ADMIN_HOME/.config/kauket" HOME="$ADMIN_HOME" "$ROOT/kauket" approve --all --yes

echo "=== get ==="
KAUKET_HOME="$MACHINE_HOME/.config/kauket" HOME="$MACHINE_HOME" "$ROOT/kauket" get ssh.main_private_key

RESOLVED_MACHINE_HOME=$(cd "$MACHINE_HOME" && pwd -P)

echo "=== verify install ==="
test -f "$RESOLVED_MACHINE_HOME/.ssh/main_private_key"
ssh-keygen -y -f "$RESOLVED_MACHINE_HOME/.ssh/main_private_key" >/dev/null
cmp "$ADMIN_HOME/.ssh/main_private_key.pem" "$RESOLVED_MACHINE_HOME/.ssh/main_private_key"

echo "=== verify permissions ==="
if [ "$(uname)" = "Darwin" ]; then
  stat_mode() { stat -f %Lp "$1"; }
else
  stat_mode() { stat -c %a "$1"; }
fi
test "$(stat_mode "$RESOLVED_MACHINE_HOME/.ssh")" = "700"
test "$(stat_mode "$RESOLVED_MACHINE_HOME/.ssh/main_private_key")" = "600"

echo "=== leak scan ==="
"$repo_root/scripts/leak-scan.sh" "$ADMIN_HOME/.config/kauket/repo" "ssh.main_private_key" "main_private_key" "machine2" "r730xd" "BEGIN OPENSSH"

echo "=== ALL GREEN ==="
