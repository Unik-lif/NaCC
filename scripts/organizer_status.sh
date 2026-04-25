#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/harness_lib.sh"

active_dir="$repo_root/docs/workflow/tasks/active"
state_file="$(harness_organizer_state_file "$repo_root")"

dispatch_state_for() {
  local packet="$1"
  local role="$2"
  local signature="$3"

  harness_dispatch_state_for_packet "$state_file" "$packet" "$role" "$signature"
}

if [[ ! -d "$active_dir" ]]; then
  echo "no active task directory: $active_dir"
  exit 0
fi

mapfile -t files < <(harness_sort_active_packets "$active_dir")

if [[ "${#files[@]}" -eq 0 ]]; then
  echo "no active task packets"
  exit 0
fi

declare -A claimed_roles=()

printf '%-24s %-4s %-10s %-4s %-14s %-14s %-18s %-22s %s\n' "TASK" "LANE" "TYPE" "PRI" "STATUS" "OWNER" "NEXT_ROLE" "DISPATCH" "GOAL"
printf '%-24s %-4s %-10s %-4s %-14s %-14s %-18s %-22s %s\n' "----" "----" "----" "---" "------" "-----" "---------" "--------" "----"

for file in "${files[@]}"; do
  task_id="$(harness_task_id "$file")"
  lane="$(harness_extract_lane "$file")"
  packet_type="$(harness_extract_packet_type "$file")"
  priority="$(harness_extract_field "$file" "Priority")"
  status="$(harness_extract_field "$file" "Status")"
  owner="$(harness_extract_field "$file" "Owner Role")"
  goal="$(harness_extract_field "$file" "Goal")"
  infer_output="$(harness_infer_next_role "$file")"
  role="${infer_output%%$'\t'*}"
  infer_output="${infer_output#*$'\t'}"
  reason="${infer_output%%$'\t'*}"
  action_state="${infer_output#*$'\t'}"
  display_role="${role:--}"
  if [[ "$action_state" != "dispatch" ]]; then
    display_role="--"
  fi

  dispatch="waiting-human"
  archive_blocker="$(harness_active_done_predecessor_for_packet "$active_dir" "$file" || true)"
  if [[ -n "$archive_blocker" ]]; then
    archive_blocker_task_id="$(harness_task_id "$archive_blocker")"
    dispatch="awaiting-archive:${archive_blocker_task_id:-$(basename "$archive_blocker")}"
  elif [[ "$action_state" == "dispatch" && -n "$role" ]]; then
    if [[ -n "${claimed_roles[$role]:-}" && "${claimed_roles[$role]}" != "${task_id:-$(basename "$file")}" ]]; then
      dispatch="role-busy:${claimed_roles[$role]}"
    else
      claimed_roles[$role]="${task_id:-$(basename "$file")}"
      sig="$(harness_dispatch_signature "$file" "$role")"
      dispatch="$(dispatch_state_for "$file" "$role" "$sig")"
    fi
  elif [[ "$action_state" == "no-action" ]]; then
    dispatch="no-action"
  fi

  printf '%-24s %-4s %-10s %-4s %-14s %-14s %-18s %-22s %s\n' \
    "${task_id:-$(basename "$file")}" \
    "${lane:--}" \
    "${packet_type:--}" \
    "${priority:--}" \
    "${status:--}" \
    "${owner:--}" \
    "$display_role" \
    "$dispatch" \
    "${goal:--}"
done
