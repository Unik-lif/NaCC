#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/harness_lib.sh"
template="$repo_root/docs/workflow/TASK_PACKET_TEMPLATE.md"
target_dir="$repo_root/docs/workflow/tasks/active"
lane=""
packet_type="execution"
goal=""
scope=""
constraints=""
dod=""
critical_intent=""
human_concern=""
key_assumptions=""
name=""

usage() {
  echo "usage: scripts/new_task_packet.sh [--lane A|B|C] [--type execution|planning|analysis] [--goal <text>] [--constraints <text>] [--dod <text>] [--scope <text>] [--critical-intent <text>] [--human-concern <text>] [--assumptions <text>] task_name" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lane)
      lane="${2:-}"
      shift 2
      ;;
    --type)
      packet_type="${2:-}"
      shift 2
      ;;
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
      if [[ -n "$name" ]]; then
        usage
        exit 1
      fi
      name="$1"
      shift
      ;;
  esac
done

if [[ -z "$name" ]]; then
  usage
  exit 1
fi

case "$packet_type" in
  execution|planning|analysis) ;;
  *)
    echo "invalid packet type: $packet_type" >&2
    usage
    exit 1
    ;;
esac

if [[ -z "$lane" ]]; then
  case "$packet_type" in
    execution) lane="A" ;;
    planning) lane="B" ;;
    analysis) lane="C" ;;
  esac
fi

case "$lane" in
  A|B|C) ;;
  *)
    echo "invalid lane: $lane" >&2
    usage
    exit 1
    ;;
esac

slug="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/_/g; s/_\\+/_/g; s/^_//; s/_$//')"
date_tag="$(date '+%Y%m%d_%H%M%S')"
created="$(date '+%Y-%m-%d %H:%M:%S %z')"
task_id="TASK_${date_tag}_${slug}"
target="$target_dir/${task_id}.md"

mkdir -p "$target_dir"

sed \
  -e "s/TASK_<timestamp>_<slug>/${task_id}/" \
  -e "s/<yyyy-mm-dd hh:mm:ss zzz>/${created}/" \
  -e "s/<lane>/${lane}/" \
  -e "s/<packet_type>/${packet_type}/" \
  "$template" >"$target"

harness_set_field "$target" "Owner Role" "human"
if [[ -n "$goal" ]]; then
  harness_set_field "$target" "Goal" "$goal"
fi
if [[ -n "$scope" ]]; then
  harness_set_field "$target" "Scope" "$scope"
fi
if [[ -n "$constraints" ]]; then
  harness_set_field "$target" "Constraints" "$constraints"
fi
if [[ -n "$dod" ]]; then
  harness_set_field "$target" "Definition Of Done" "$dod"
fi
if [[ -n "$critical_intent" ]]; then
  harness_set_field "$target" "Critical Intent" "$critical_intent"
fi
if [[ -n "$human_concern" ]]; then
  harness_set_field "$target" "Human Concern" "$human_concern"
fi
if [[ -n "$key_assumptions" ]]; then
  harness_set_field "$target" "Key Assumptions" "$key_assumptions"
fi

report_path="$(harness_ensure_human_report "$target" "$repo_root")"
seeded="no"
if harness_packet_has_planner_seed "$target"; then
  seeded="yes"
fi

echo "created $target"
echo "human report: $report_path"
echo "lane: $lane"
echo "type: $packet_type"
echo "seeded: $seeded"
echo "next:"
if [[ "$seeded" == "yes" ]]; then
  echo "  1. planner can start immediately from the packet"
  echo "  2. let organizer dispatch planner or launch planner directly"
  echo "  3. planner should turn the seeded intent into a bounded route and next handoff"
else
  echo "  1. add the first human seed before launching planner"
  echo "     recommended minimum: Goal"
  echo "  2. use scripts/seed_task_packet.sh $target --goal \"...\" [--constraints \"...\"] [--dod \"...\"]"
  echo "  3. then let organizer dispatch planner or launch planner directly"
fi
