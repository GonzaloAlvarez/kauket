#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  cat >&2 <<EOF
usage: leak-scan.sh <scan-dir> [word ...]
  Scans <scan-dir> for each word (case-insensitive) using grep -R -I -i.
  Exit 0 if no matches; exit 1 if any matches found.
  Defaults to the spec §13.2 wordlist if none provided.
EOF
  exit 2
fi

scan_dir="$1"
shift

if [ "$#" -eq 0 ]; then
  set -- "ssh.main_private_key" "main_private_key" "machine2" "r730xd" "BEGIN OPENSSH"
fi

bad=0
for w in "$@"; do
  if hits=$(grep -R -I -i -l "$w" "$scan_dir" 2>/dev/null); then
    if [ -n "$hits" ]; then
      echo "LEAK '$w' in:"
      printf '%s\n' "$hits" | sed 's/^/  /'
      bad=1
    fi
  fi
done

exit "$bad"
