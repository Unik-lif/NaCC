#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/harness_lib.sh"

focus_mode=0
print_target=0
packet="${1:-}"
role="${2:-}"

usage() {
  echo "usage: scripts/tmux_launch_role.sh [--focus] [--print-target] <task-packet-path> <role>" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --focus)
      focus_mode=1
      shift
      ;;
    --print-target)
      print_target=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      break
      ;;
  esac
done

packet="${1:-}"
role="${2:-}"

if [[ -z "$packet" || -z "$role" ]]; then
  usage
  exit 1
fi

if ! harness_tmux_available; then
  echo "tmux is required for tmux_launch_role.sh" >&2
  exit 1
fi

harness_tmux_sync_launch_environment

packet="$(harness_resolve_packet_path "$packet" "$repo_root" || true)"
if [[ -z "$packet" ]]; then
  echo "task packet not found" >&2
  exit 1
fi

if ! harness_is_supported_role "$role"; then
  echo "unsupported role: $role" >&2
  exit 1
fi

session_name="$(harness_tmux_current_session)"
window_name="$(harness_tmux_role_window_name "$role" || true)"
pane_title="$(harness_tmux_role_pane_title "$role" || true)"
pane_id=""
signature="$(harness_dispatch_signature "$packet" "$role")"

if [[ -n "$pane_title" ]]; then
  pane_id="$(harness_tmux_ensure_role_pane "$role" "$repo_root" || true)"
  if [[ -z "$pane_id" ]]; then
    pane_id="$(harness_tmux_find_pane_by_role "$role" || true)"
  fi
fi

if [[ -z "$pane_id" && -n "$pane_title" ]]; then
  # Repair the fixed control-room layout before drifting into disposable fallback windows.
  "$repo_root/scripts/start_control_room.sh" >/dev/null 2>&1 || true
  pane_id="$(harness_tmux_ensure_role_pane "$role" "$repo_root" || true)"
  if [[ -z "$pane_id" ]]; then
    pane_id="$(harness_tmux_find_pane_by_role "$role" || true)"
  fi
fi

if [[ -n "$pane_id" ]]; then
  if [[ "$print_target" -eq 1 ]]; then
    printf 'pane\t%s\t%s\t%s\n' "$pane_id" "$window_name" "$pane_title"
    exit 0
  fi

  harness_tmux_set_dispatch_metadata "$pane_id" "$packet" "$role" "$signature"
  tmux respawn-pane -k -t "$pane_id" "cd '$repo_root' && exec scripts/run_role_session.sh '$packet' '$role'"
  if [[ "$focus_mode" -eq 1 ]]; then
    tmux select-window -t "${session_name}:${window_name}"
    tmux select-pane -t "$pane_id"
  fi
  printf 'pane\t%s\t%s\t%s\n' "$pane_id" "$window_name" "$pane_title"
  exit 0
fi

task_id="$(harness_task_id "$packet")"
fallback_window="nacc-${role}-${task_id:-task}-$(date '+%H%M%S')"

if [[ "$print_target" -eq 1 ]]; then
  printf 'window\t%s\t-\t-\n' "$fallback_window"
  exit 0
fi

if [[ "$focus_mode" -eq 1 ]]; then
  pane_id="$(tmux new-window -P -F '#{pane_id}' -n "$fallback_window" -c "$repo_root" \
    "cd '$repo_root' && exec scripts/run_role_session.sh '$packet' '$role'"
  )"
else
  pane_id="$(tmux new-window -d -P -F '#{pane_id}' -n "$fallback_window" -c "$repo_root" \
    "cd '$repo_root' && exec scripts/run_role_session.sh '$packet' '$role'"
  )"
fi

if [[ -n "$pane_id" ]]; then
  harness_tmux_set_dispatch_metadata "$pane_id" "$packet" "$role" "$signature"
fi

printf 'window\t%s\t-\t-\n' "$fallback_window"
