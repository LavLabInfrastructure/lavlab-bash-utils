#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"

files=("${ROOT}/functions.bash")
while IFS= read -r -d '' file; do
  files+=("$file")
done < <(find "${ROOT}/commands" -type f -maxdepth 1 -print0)

for file in "${files[@]}"; do
  printf 'Checking %s\n' "$file"
  bash -n "$file"
  chmod +x "$file" >/dev/null 2>&1 || true
done

printf 'All scripts passed bash -n\n'
