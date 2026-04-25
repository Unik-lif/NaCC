#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
restart_mode=0

usage() {
  echo "usage: scripts/start_organizer.sh [--restart] [--interval <seconds>]" >&2
}

interval_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --restart)
      restart_mode=1
      shift
      ;;
    --interval)
      interval_args+=("$1" "${2:-}")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

if ! source "$repo_root/scripts/harness_lib.sh" 2>/dev/null; then
  :
fi

if ! harness_tmux_available; then
  echo "start_organizer.sh is intended to be run inside tmux." >&2
  echo "Fallback command:" >&2
  echo "  scripts/organizer_loop.sh --launch ${interval_args[*]}" >&2
  exit 1
fi

organizer_loop_running() {
  ps -ef | grep -F "$repo_root/scripts/organizer_loop.sh --launch" | grep -v grep >/dev/null 2>&1
}

organizer_pane="$(harness_tmux_find_pane_by_role organizer || true)"
if [[ -z "$organizer_pane" ]]; then
  "$repo_root/scripts/start_control_room.sh"
  organizer_pane="$(harness_tmux_find_pane_by_role organizer || true)"
fi

if [[ -z "$organizer_pane" ]]; then
  echo "organizer pane not found after control-room setup" >&2
  exit 1
fi

if [[ "$restart_mode" -ne 1 ]] && organizer_loop_running; then
  tmux select-window -t "$(harness_tmux_current_session):agents"
  tmux select-pane -t "$organizer_pane"
  exit 0
fi

harness_tmux_sync_launch_environment

tmux respawn-pane -k -t "$organizer_pane" \
  "cd '$repo_root' && exec scripts/organizer_loop.sh --launch ${interval_args[*]}"
tmux select-window -t "$(harness_tmux_current_session):agents"
tmux select-pane -t "$organizer_pane"
