#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/harness_lib.sh"
launch_mode=0
packet=""
active_dir="$repo_root/docs/workflow/tasks/active"

usage() {
  echo "usage: scripts/start_next_role.sh [--launch] <task-packet-path>" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --launch)
      launch_mode=1
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

archive_blocker="$(harness_active_done_predecessor_for_packet "$active_dir" "$packet" || true)"
if [[ -n "$archive_blocker" ]]; then
  archive_blocker_task_id="$(harness_task_id "$archive_blocker")"
  if [[ "$launch_mode" -eq 1 ]]; then
    if archive_output="$("$repo_root/scripts/archive_task_packet.sh" "$archive_blocker" 2>&1)"; then
      printf '%s\n' "$archive_output"
    else
      printf '%s\n' "$archive_output" >&2
      exit 1
    fi
  else
    echo "Blocked by unarchived completed predecessor: ${archive_blocker_task_id:-$(basename "$archive_blocker")}" >&2
    echo "Archive it first:" >&2
    echo "  scripts/archive_task_packet.sh $archive_blocker" >&2
    exit 1
  fi
fi

task_id="$(harness_task_id "$packet")"
status="$(harness_extract_field "$packet" "Status")"
owner="$(harness_extract_field "$packet" "Owner Role")"
next_owner="$(harness_extract_next_owner "$packet")"
infer_output="$(harness_infer_next_role "$packet")"
role="${infer_output%%$'\t'*}"
infer_output="${infer_output#*$'\t'}"
reason="${infer_output%%$'\t'*}"
action_state="${infer_output#*$'\t'}"

if [[ "$action_state" == "waiting-human" && "$status" == "draft" ]] && ! harness_packet_has_planner_seed "$packet"; then
  role="planner"
  reason="explicit human launch on blank draft packet"
  action_state="dispatch"
fi

if [[ "$action_state" == "waiting-human" ]] && harness_packet_waits_for_human_checkpoint "$packet"; then
  role="$(harness_packet_checkpoint_target_role "$packet" || true)"
  if [[ -n "$role" ]]; then
    reason="explicit human launch on checkpointed machine handoff"
    action_state="dispatch"
  fi
fi

if [[ "$action_state" != "dispatch" || -z "$role" ]]; then
  echo "Task: ${task_id:-$(basename "$packet")}"
  echo "Status: ${status:--}"
  echo "Current owner: ${owner:--}"
  echo "Next owner: ${next_owner:--}"
  echo
  if [[ "$action_state" == "waiting-human" ]]; then
    echo "No agent launch recommended."
    echo "Reason: $reason"
    if ! harness_packet_has_planner_seed "$packet"; then
      echo
      echo "Seed the packet first:"
      echo "  scripts/seed_task_packet.sh $packet --goal \"...\" [--constraints \"...\"] [--dod \"...\"]"
    fi
  else
    echo "Could not infer a supported next role automatically."
    echo "Reason: $reason"
    echo "Use scripts/harness_next.sh $packet to inspect the packet state."
    echo "Then run scripts/launch_prompt.sh $packet <role> manually."
  fi
  exit 1
fi

echo "Task: ${task_id:-$(basename "$packet")}"
echo "Detected next role: $role"
echo "Reason: $reason"
echo

if [[ "$launch_mode" -eq 1 ]]; then
  if harness_tmux_available; then
    launch_result="$("$repo_root/scripts/tmux_launch_role.sh" --focus "$packet" "$role")"
    launch_type="$(printf '%s\n' "$launch_result" | awk -F'\t' 'NR==1 { print $1 }')"
    launch_id="$(printf '%s\n' "$launch_result" | awk -F'\t' 'NR==1 { print $2 }')"
    launch_window="$(printf '%s\n' "$launch_result" | awk -F'\t' 'NR==1 { print $3 }')"
    launch_label="$(printf '%s\n' "$launch_result" | awk -F'\t' 'NR==1 { print $4 }')"
    if [[ "$launch_type" == "pane" ]]; then
      launch_target="${launch_label:-$launch_id}"
    else
      launch_target="$launch_id"
    fi
    echo "Launch target: ${launch_type}:${launch_target}"
    echo "Packet: $packet"
    echo "Role: $role"
  else
    exec "$repo_root/scripts/run_role_session.sh" "$packet" "$role"
  fi
else
  "$repo_root/scripts/launch_prompt.sh" "$packet" "$role"
fi
