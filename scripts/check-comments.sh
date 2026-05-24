#!/usr/bin/env bash
set -euo pipefail

bad=0

while IFS= read -r file; do
  while IFS= read -r line; do
    case "$line" in
      *"//go:"*) continue ;;
      *"Code generated"*) continue ;;
      *"// +build"*) continue ;;
      *"// "*)
        echo "comment found: $file: $line"
        bad=1
        ;;
      *"/*"*)
        echo "block comment found: $file: $line"
        bad=1
        ;;
    esac
  done < "$file"
done < <(find . -name '*.go' -not -path './vendor/*' -not -path './.git/*')

exit "$bad"
