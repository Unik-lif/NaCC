#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/harness_lib.sh"

restart_mode=0

usage() {
  echo "usage: scripts/start_control_room.sh [--restart]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --restart)
      restart_mode=1
      shift
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

if ! harness_tmux_available; then
  echo "start_control_room.sh is intended to be run inside tmux." >&2
  exit 1
fi

session_name="$(harness_tmux_current_session)"

set_pane_title() {
  local pane_id="$1"
  local role_name="$2"
  harness_tmux_set_pane_role "$pane_id" "$role_name"
}

set_window_role_map() {
  local window_name="$1"
  harness_tmux_assign_window_roles "$window_name"
}

ensure_window_absent_if_restarting() {
  local window_name="$1"
  if [[ "$restart_mode" -eq 1 ]] && harness_tmux_window_exists "$window_name"; then
    tmux kill-window -t "${session_name}:${window_name}"
  fi
}

ensure_agents_window() {
  local planner_pane coder_pane reviewer_pane organizer_pane

  ensure_window_absent_if_restarting "agents"
  if harness_tmux_window_exists "agents"; then
    harness_tmux_ensure_role_pane organizer "$repo_root" >/dev/null || true
    set_window_role_map "agents"
    return 0
  fi

  planner_pane="$(tmux new-window -d -P -F '#{pane_id}' -n agents -c "$repo_root")"
  coder_pane="$(tmux split-window -d -h -P -F '#{pane_id}' -t "$planner_pane" -c "$repo_root")"
  reviewer_pane="$(tmux split-window -d -v -P -F '#{pane_id}' -t "$planner_pane" -c "$repo_root")"
  organizer_pane="$(tmux split-window -d -v -P -F '#{pane_id}' -t "$coder_pane" -c "$repo_root")"
  tmux select-layout -t "${session_name}:agents" tiled >/dev/null

  set_pane_title "$planner_pane" planner
  set_pane_title "$coder_pane" coder
  set_pane_title "$reviewer_pane" reviewer
  set_pane_title "$organizer_pane" organizer
}

ensure_tests_window() {
  local test_runner_pane log_analyzer_pane

  ensure_window_absent_if_restarting "tests"
  if harness_tmux_window_exists "tests"; then
    harness_tmux_ensure_role_pane log_analyzer "$repo_root" >/dev/null || true
    set_window_role_map "tests"
    return 0
  fi

  test_runner_pane="$(tmux new-window -d -P -F '#{pane_id}' -n tests -c "$repo_root")"
  log_analyzer_pane="$(tmux split-window -d -v -P -F '#{pane_id}' -t "$test_runner_pane" -c "$repo_root")"
  tmux select-layout -t "${session_name}:tests" tiled >/dev/null

  set_pane_title "$test_runner_pane" test_runner
  set_pane_title "$log_analyzer_pane" log_analyzer
}

ensure_debug_window() {
  local qemu_pane vm_pane gdb_pane logger_pane

  ensure_window_absent_if_restarting "debug"
  if harness_tmux_window_exists "debug"; then
    harness_tmux_ensure_role_pane logger "$repo_root" >/dev/null || true
    set_window_role_map "debug"
    return 0
  fi

  qemu_pane="$(tmux new-window -d -P -F '#{pane_id}' -n debug -c "$repo_root")"
  vm_pane="$(tmux split-window -d -h -P -F '#{pane_id}' -t "$qemu_pane" -c "$repo_root")"
  gdb_pane="$(tmux split-window -d -v -P -F '#{pane_id}' -t "$qemu_pane" -c "$repo_root")"
  logger_pane="$(tmux split-window -d -v -P -F '#{pane_id}' -t "$vm_pane" -c "$repo_root")"
  tmux select-layout -t "${session_name}:debug" tiled >/dev/null

  set_pane_title "$qemu_pane" qemu
  set_pane_title "$vm_pane" vm
  set_pane_title "$gdb_pane" gdb
  set_pane_title "$logger_pane" logger
}

ensure_agents_window
ensure_tests_window
ensure_debug_window

tmux select-window -t "${session_name}:agents"
planner_pane="$(harness_tmux_find_pane_by_role planner)"
if [[ -n "$planner_pane" ]]; then
  tmux select-pane -t "$planner_pane"
fi
