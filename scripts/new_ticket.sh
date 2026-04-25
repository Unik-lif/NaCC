#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
template="$repo_root/docs/workflow/IMPLEMENTATION_TICKET_TEMPLATE.md"
name="${1:-}"

if [[ -z "$name" ]]; then
  echo "usage: scripts/new_ticket.sh ticket_name" >&2
  exit 1
fi

slug="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/_/g; s/_\\+/_/g; s/^_//; s/_$//')"
date_tag="$(date '+%Y%m%d_%H%M%S')"
target="$repo_root/docs/workflow/TICKET_${date_tag}_${slug}.md"

cp "$template" "$target"
echo "created $target"
