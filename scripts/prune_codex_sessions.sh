#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/prune_codex_sessions.sh [options]

Delete Codex rollout files that have not been updated for more than N days.
Defaults to a dry run so you can review the candidates first.

Options:
  --apply               Actually delete the stale session files.
  --days <n>            Delete sessions older than <n> days. Default: 7.
  --codex-home <dir>    Codex home directory. Default: $CODEX_HOME or ~/.codex.
  -h, --help            Show this help message.

Behavior:
  - Targets rollout files under <codex-home>/sessions.
  - Uses file mtime as the freshness signal.
  - When --apply is used, also prunes matching entries from
    <codex-home>/session_index.jsonl when possible.

Examples:
  scripts/prune_codex_sessions.sh
  scripts/prune_codex_sessions.sh --days 14
  scripts/prune_codex_sessions.sh --apply
  scripts/prune_codex_sessions.sh --codex-home /tmp/test-codex --apply
EOF
}

human_size() {
  local bytes="$1"
  if command -v numfmt >/dev/null 2>&1; then
    numfmt --to=iec-i --suffix=B "$bytes"
  else
    printf '%sB\n' "$bytes"
  fi
}

days=7
apply=0
codex_home="${CODEX_HOME:-$HOME/.codex}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)
      apply=1
      shift
      ;;
    --days)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --days" >&2
        exit 1
      fi
      days="$2"
      shift 2
      ;;
    --codex-home)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --codex-home" >&2
        exit 1
      fi
      codex_home="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! "$days" =~ ^[0-9]+$ ]]; then
  echo "--days must be a non-negative integer" >&2
  exit 1
fi

codex_home="$(cd "$codex_home" 2>/dev/null && pwd || true)"
if [[ -z "$codex_home" ]]; then
  echo "failed to resolve Codex home directory" >&2
  exit 1
fi

session_root="$codex_home/sessions"
session_index="$codex_home/session_index.jsonl"

if [[ ! -d "$session_root" ]]; then
  echo "no Codex sessions directory: $session_root"
  exit 0
fi

declare -a stale_files=()
while IFS= read -r -d '' file; do
  stale_files+=("$file")
done < <(find "$session_root" -type f -name 'rollout-*.jsonl' -mtime +"$days" -print0)

if [[ "${#stale_files[@]}" -eq 0 ]]; then
  echo "no Codex sessions older than $days days under $session_root"
  exit 0
fi

ids_file="$(mktemp)"
tmp_index=""
cleanup() {
  rm -f -- "$ids_file"
  if [[ -n "$tmp_index" ]]; then
    rm -f -- "$tmp_index"
  fi
}
trap cleanup EXIT

total_bytes=0
echo "stale Codex sessions older than $days days:"
for file in "${stale_files[@]}"; do
  bytes="$(stat -c %s "$file")"
  total_bytes=$((total_bytes + bytes))
  name="$(basename "$file")"
  if [[ "$name" =~ ^rollout-.*-([0-9a-f-]{36})\.jsonl$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}" >> "$ids_file"
  fi
  printf '  %s  %s\n' "$(human_size "$bytes")" "$file"
done

echo
echo "candidate files: ${#stale_files[@]}"
echo "total size: $(human_size "$total_bytes")"

if [[ "$apply" -ne 1 ]]; then
  echo
  echo "dry run only; rerun with --apply to delete these sessions"
  exit 0
fi

for file in "${stale_files[@]}"; do
  rm -f -- "$file"
done

find "$session_root" -depth -type d -empty -delete

if [[ -s "$ids_file" && -f "$session_index" ]]; then
  tmp_index="$(mktemp)"
  awk '
    NR == FNR {
      deleted[$0] = 1
      next
    }
    match($0, /"id":"([^"]+)"/, m) {
      if (m[1] in deleted) {
        next
      }
    }
    { print }
  ' "$ids_file" "$session_index" > "$tmp_index"
  mv "$tmp_index" "$session_index"
  tmp_index=""
fi

echo
echo "deleted ${#stale_files[@]} stale Codex session files"
