#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/graphify-out}"
OUT="$(python3 -c 'import os, sys; print(os.path.abspath(sys.argv[1]))' "$OUT")"

if [[ "$OUT" == "/" || "$OUT" == "$ROOT" ]]; then
  printf 'Refusing unsafe Graphify output path: %s\n' "$OUT" >&2
  exit 2
fi

if ! command -v graphify >/dev/null 2>&1; then
  cat >&2 <<'HELP'
Graphify is not installed.
Install the official `graphifyy` package in a networked environment:
  uv tool install graphifyy==0.9.26
Then rerun:
  make graph
HELP
  exit 127
fi

OUT_PARENT="$(dirname "$OUT")"
mkdir -p "$OUT_PARENT"
if [[ -e "$OUT" && ! -f "$OUT/graph.json" ]]; then
  printf 'Refusing to replace existing non-Graphify output path: %s\n' "$OUT" >&2
  exit 2
fi
TMP_OUT="$(mktemp -d "$OUT_PARENT/.graphify-next.XXXXXX")"
BACKUP_OUT=""

cleanup() {
  if [[ -n "${TMP_OUT:-}" && -e "$TMP_OUT" ]]; then
    rm -rf -- "$TMP_OUT"
  fi
  if [[ -n "${BACKUP_OUT:-}" && -e "$BACKUP_OUT" ]]; then
    if [[ ! -e "$OUT" ]]; then
      if mv -- "$BACKUP_OUT" "$OUT"; then
        BACKUP_OUT=""
      else
        printf 'WARNING: previous Graphify output preserved at %s\n' "$BACKUP_OUT" >&2
      fi
    else
      printf 'WARNING: previous Graphify output preserved at %s\n' "$BACKUP_OUT" >&2
    fi
  fi
}
trap cleanup EXIT

graphify extract "$ROOT" --code-only --out "$TMP_OUT" --force
python3 "$ROOT/scripts/checks/check_graphify_output.py" "$TMP_OUT/graph.json"

if [[ -e "$OUT" ]]; then
  BACKUP_OUT="$(mktemp -d "$OUT_PARENT/.graphify-prev.XXXXXX")"
  rmdir "$BACKUP_OUT"
  mv -- "$OUT" "$BACKUP_OUT"
fi

if ! mv -- "$TMP_OUT" "$OUT"; then
  if [[ -n "$BACKUP_OUT" && -e "$BACKUP_OUT" && ! -e "$OUT" ]]; then
    mv -- "$BACKUP_OUT" "$OUT"
    BACKUP_OUT=""
  fi
  exit 1
fi
TMP_OUT=""

if [[ -n "$BACKUP_OUT" && -e "$BACKUP_OUT" ]]; then
  rm -rf -- "$BACKUP_OUT"
  BACKUP_OUT=""
fi

printf 'Graphify output written under %s\n' "$OUT"
