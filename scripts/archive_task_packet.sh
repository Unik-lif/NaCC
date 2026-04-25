#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/harness_lib.sh"

force_mode=0
packet=""

usage() {
  echo "usage: scripts/archive_task_packet.sh [--force] <task-packet-path>" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)
      force_mode=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ -n "$packet" ]]; then
        usage
        exit 1
      fi
      packet="$1"
      shift
      ;;
  esac
done

if [[ -z "$packet" ]]; then
  usage
  exit 1
fi

packet="$(harness_resolve_packet_path "$packet" "$repo_root" || true)"
if [[ -z "$packet" ]]; then
  echo "task packet not found" >&2
  exit 1
fi
if [[ "$packet" != /* ]]; then
  packet="$repo_root/$packet"
fi

active_dir="$repo_root/docs/workflow/tasks/active"
completed_dir="$repo_root/docs/workflow/tasks/completed"

case "$packet" in
  "$active_dir"/*) ;;
  *)
    echo "packet is not under active/: $packet" >&2
    exit 1
    ;;
esac

status="$(harness_extract_field "$packet" "Status")"
if [[ "$force_mode" -ne 1 && "$status" != "done" ]]; then
  echo "refusing to archive non-done packet (status=$status). Use --force if you really want this." >&2
  exit 1
fi

mkdir -p "$completed_dir"
target="$completed_dir/$(basename "$packet")"
if [[ -e "$target" ]]; then
  echo "completed packet already exists: $target" >&2
  exit 1
fi

task_id="$(harness_task_id "$packet")"
active_report="$(harness_human_report_path_for_task_id "$repo_root" "active" "$task_id")"
completed_report="$(harness_human_report_path_for_task_id "$repo_root" "completed" "$task_id")"
state_file="$(harness_organizer_state_file "$repo_root")"

if [[ -f "$active_report" && -e "$completed_report" ]]; then
  echo "completed human report already exists: $completed_report" >&2
  exit 1
fi

retired_panes="$(
  harness_tmux_retire_packet_panes "$packet" "$repo_root" 2>/dev/null || true
)"

mv "$packet" "$target"
echo "archived $packet -> $target"

if [[ -f "$active_report" ]]; then
  mkdir -p "$(dirname "$completed_report")"
  mv "$active_report" "$completed_report"
  echo "archived $active_report -> $completed_report"
fi

if [[ -f "$state_file" ]]; then
  tmp_state="$(mktemp "${TMPDIR:-/tmp}/nacc-harness-state.XXXXXX")"
  pruned_rows=0

  while IFS= read -r line || [[ -n "$line" ]]; do
    state_packet="${line%%$'\t'*}"
    if [[ -z "$state_packet" || "$state_packet" == "$packet" || ! -f "$state_packet" ]]; then
      pruned_rows=$((pruned_rows + 1))
      continue
    fi
    printf '%s\n' "$line" >>"$tmp_state"
  done < "$state_file"

  mv "$tmp_state" "$state_file"
  if [[ "$pruned_rows" -gt 0 ]]; then
    echo "pruned $pruned_rows organizer state row(s)"
  fi
fi

if [[ -n "$retired_panes" ]]; then
  retired_count="$(printf '%s\n' "$retired_panes" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [[ "$retired_count" -gt 0 ]]; then
    echo "retired $retired_count tmux pane(s) for archived packet"
  fi
fi
