#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
active_dir="$repo_root/docs/workflow/tasks/active"
source "$repo_root/scripts/harness_lib.sh"

if [[ ! -d "$active_dir" ]]; then
  echo "no active task directory: $active_dir"
  exit 0
fi

mapfile -t files < <(harness_sort_active_packets "$active_dir")

if [[ "${#files[@]}" -eq 0 ]]; then
  echo "no active task packets"
  exit 0
fi

printf '%-28s %-4s %-10s %-14s %-14s %-14s %s\n' "TASK" "LANE" "TYPE" "STATUS" "OWNER" "NEXT_OWNER" "GOAL"
printf '%-28s %-4s %-10s %-14s %-14s %-14s %s\n' "----" "----" "----" "------" "-----" "----------" "----"

for file in "${files[@]}"; do
  task_id="$(harness_task_id "$file")"
  lane="$(harness_extract_lane "$file")"
  packet_type="$(harness_extract_packet_type "$file")"
  status="$(harness_extract_field "$file" "Status")"
  owner="$(harness_extract_field "$file" "Owner Role")"
  goal="$(harness_extract_field "$file" "Goal")"
  next_owner="$(harness_extract_next_owner "$file")"

  printf '%-28s %-4s %-10s %-14s %-14s %-14s %s\n' \
    "${task_id:-$(basename "$file")}" \
    "${lane:--}" \
    "${packet_type:--}" \
    "${status:--}" \
    "${owner:--}" \
    "${next_owner:--}" \
    "${goal:--}"
done
