#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/harness_lib.sh"

launch_mode=0
current_packet=""
task_name=""
rough_idea=""

usage() {
  echo "usage: scripts/spawn_next_planning_lane.sh [--launch] <current-packet> <task_name> [rough_idea...]" >&2
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
      if [[ -z "$current_packet" ]]; then
        current_packet="$1"
      elif [[ -z "$task_name" ]]; then
        task_name="$1"
      else
        rough_idea="${rough_idea:+$rough_idea }$1"
      fi
      shift
      ;;
  esac
done

if [[ -z "$current_packet" || -z "$task_name" ]]; then
  usage
  exit 1
fi

current_packet="$(harness_resolve_packet_path "$current_packet" "$repo_root" || true)"
if [[ -z "$current_packet" ]]; then
  echo "current task packet not found" >&2
  exit 1
fi

current_task_id="$(harness_task_id "$current_packet")"
current_priority="$(harness_extract_field "$current_packet" "Priority")"
if ! harness_has_meaningful_value "$current_priority"; then
  current_priority="P2"
fi

if [[ -z "$rough_idea" ]]; then
  rough_idea="Shape the next bounded step after ${current_task_id:-the current execution packet} while lane A continues."
fi

output="$("$repo_root/scripts/new_task_packet.sh" --type planning "$task_name")"
printf '%s\n' "$output"
planning_packet="$(printf '%s\n' "$output" | awk '/^created / { print $2; exit }')"
if [[ -z "$planning_packet" ]]; then
  echo "failed to create planning packet" >&2
  exit 1
fi

harness_set_field "$planning_packet" "Priority" "$current_priority"
harness_set_field "$planning_packet" "Owner Role" "planner"
harness_set_field "$planning_packet" "Status" "in_progress"
harness_set_field "$planning_packet" "Goal" "$rough_idea"
harness_set_field "$planning_packet" "Constraints" "Lane B planning while lane A continues. Do not reopen or redefine lane A unless the human explicitly asks."
harness_set_field "$planning_packet" "Definition Of Done" "Produce a bounded next-step route or planning packet that the human can queue without interrupting the current execution lane."
harness_set_field "$planning_packet" "Related Ticket / Plan" "$current_packet"
harness_set_field "$planning_packet" "Next owner" "planner"

echo
echo "Prepared lane B planning packet:"
echo "- Packet: $planning_packet"
echo "- Related execution packet: $current_packet"
echo "- Goal: $rough_idea"
echo

if [[ "$launch_mode" -eq 1 ]]; then
  "$repo_root/scripts/start_next_role.sh" --launch "$planning_packet"
else
  echo "Next step:"
  echo "  scripts/start_next_role.sh --launch $planning_packet"
fi
