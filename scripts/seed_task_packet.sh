#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/harness_lib.sh"

packet=""
goal=""
scope=""
constraints=""
dod=""
critical_intent=""
human_concern=""
key_assumptions=""

usage() {
  echo "usage: scripts/seed_task_packet.sh <task-packet> [--goal <text>] [--constraints <text>] [--dod <text>] [--scope <text>] [--critical-intent <text>] [--human-concern <text>] [--assumptions <text>]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --goal)
      goal="${2:-}"
      shift 2
      ;;
    --scope)
      scope="${2:-}"
      shift 2
      ;;
    --constraints)
      constraints="${2:-}"
      shift 2
      ;;
    --dod|--definition-of-done)
      dod="${2:-}"
      shift 2
      ;;
    --critical-intent)
      critical_intent="${2:-}"
      shift 2
      ;;
    --human-concern)
      human_concern="${2:-}"
      shift 2
      ;;
    --assumptions)
      key_assumptions="${2:-}"
      shift 2
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

if ! harness_field_has_meaningful_value "$packet" "Owner Role"; then
  harness_set_field "$packet" "Owner Role" "human"
fi

if [[ -n "$goal" ]]; then
  harness_set_field "$packet" "Goal" "$goal"
fi
if [[ -n "$scope" ]]; then
  harness_set_field "$packet" "Scope" "$scope"
fi
if [[ -n "$constraints" ]]; then
  harness_set_field "$packet" "Constraints" "$constraints"
fi
if [[ -n "$dod" ]]; then
  harness_set_field "$packet" "Definition Of Done" "$dod"
fi
if [[ -n "$critical_intent" ]]; then
  harness_set_field "$packet" "Critical Intent" "$critical_intent"
fi
if [[ -n "$human_concern" ]]; then
  harness_set_field "$packet" "Human Concern" "$human_concern"
fi
if [[ -n "$key_assumptions" ]]; then
  harness_set_field "$packet" "Key Assumptions" "$key_assumptions"
fi

echo "Seeded packet:"
echo "- Packet: $packet"
if [[ -n "$goal" ]]; then
  echo "- Goal: $goal"
fi
if [[ -n "$scope" ]]; then
  echo "- Scope: $scope"
fi
if [[ -n "$constraints" ]]; then
  echo "- Constraints: $constraints"
fi
if [[ -n "$dod" ]]; then
  echo "- Definition Of Done: $dod"
fi
if [[ -n "$critical_intent" ]]; then
  echo "- Critical Intent: $critical_intent"
fi
if [[ -n "$human_concern" ]]; then
  echo "- Human Concern: $human_concern"
fi
if [[ -n "$key_assumptions" ]]; then
  echo "- Key Assumptions: $key_assumptions"
fi
echo

if harness_packet_has_planner_seed "$packet"; then
  echo "Planner can now start from this packet."
  echo "Next step:"
  echo "  scripts/start_next_role.sh --launch $packet"
else
  echo "Packet still does not have enough planner seed."
  echo "Recommended minimum: Goal"
fi
