#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/harness_lib.sh"
task_name=""
lane=""
packet_type=""
launch_mode=0
goal=""
scope=""
constraints=""
dod=""
critical_intent=""
human_concern=""
key_assumptions=""
active_dir="$repo_root/docs/workflow/tasks/active"
next_steps="$repo_root/docs/workflow/NEXT_STEPS.md"

usage() {
  echo "usage: scripts/bootstrap_harness.sh [--launch] [--lane A|B|C] [--type execution|planning|analysis] [--goal <text>] [--constraints <text>] [--dod <text>] [--scope <text>] [--critical-intent <text>] [--human-concern <text>] [--assumptions <text>] [task_name]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --launch)
      launch_mode=1
      shift
      ;;
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
      if [[ -n "$task_name" ]]; then
        usage
        exit 1
      fi
      task_name="$1"
      shift
      ;;
  esac
done

show_active_packets() {
  echo "Active packets:"
  "$repo_root/scripts/harness_status.sh"
  echo
}

show_pending_candidates() {
  echo "Top pending candidates from docs/workflow/NEXT_STEPS.md:"
  awk -F'|' '
    function trim(s) {
      gsub(/^[ \t]+|[ \t]+$/, "", s)
      return s
    }
    /^\|/ && $0 !~ /---/ {
      priority = trim($2)
      action = trim($3)
      owner = trim($4)
      status = trim($5)
      if (status == "pending") {
        print "- " priority ": " action " [" owner "]"
        count++
        if (count == 5) exit
      }
    }
  ' "$next_steps"
  echo
}

find_active_packets() {
  harness_sort_active_packets "$active_dir"
}

is_nonterminal_packet() {
  local packet="$1"
  local status
  status="$(harness_extract_field "$packet" "Status")"
  [[ "$status" != "done" ]]
}

count_active_packets_by_type() {
  local target_type="$1"
  local packet count=0
  while IFS= read -r packet; do
    [[ -n "$packet" ]] || continue
    [[ "$(harness_extract_packet_type "$packet")" == "$target_type" ]] || continue
    is_nonterminal_packet "$packet" || continue
    count=$((count + 1))
  done < <(find_active_packets)
  printf '%s\n' "$count"
}

if [[ -n "$task_name" ]]; then
  new_packet_args=()
  [[ -n "$lane" ]] && new_packet_args+=(--lane "$lane")
  [[ -n "$packet_type" ]] && new_packet_args+=(--type "$packet_type")
  [[ -n "$goal" ]] && new_packet_args+=(--goal "$goal")
  [[ -n "$scope" ]] && new_packet_args+=(--scope "$scope")
  [[ -n "$constraints" ]] && new_packet_args+=(--constraints "$constraints")
  [[ -n "$dod" ]] && new_packet_args+=(--dod "$dod")
  [[ -n "$critical_intent" ]] && new_packet_args+=(--critical-intent "$critical_intent")
  [[ -n "$human_concern" ]] && new_packet_args+=(--human-concern "$human_concern")
  [[ -n "$key_assumptions" ]] && new_packet_args+=(--assumptions "$key_assumptions")
  output="$("$repo_root/scripts/new_task_packet.sh" "${new_packet_args[@]}" "$task_name")"
  printf '%s\n' "$output"
  packet_path="$(printf '%s\n' "$output" | awk '/^created / { print $2; exit }')"
  report_path="$(printf '%s\n' "$output" | awk '/^human report: / { print $3; exit }')"
  lane_value="$(printf '%s\n' "$output" | awk '/^lane: / { print $2; exit }')"
  type_value="$(printf '%s\n' "$output" | awk '/^type: / { print $2; exit }')"
  seeded_value="$(printf '%s\n' "$output" | awk '/^seeded: / { print $2; exit }')"
  echo
  echo "Next steps:"
  echo "1. Confirm Lane=$lane_value and Packet Type=$type_value fit this round."
  echo "2. If you are using the full multi-window organizer flow, make sure these are running first:"
  echo
  echo "   scripts/start_control_room.sh --restart"
  echo "   scripts/start_organizer.sh --restart"
  echo
  echo "   then organizer should dispatch planner automatically."
  echo
  if [[ "$seeded_value" == "yes" ]]; then
    echo "3. The packet is already seeded enough for planner."
    echo
    echo "   scripts/start_next_role.sh --launch $packet_path"
    echo "4. Planner should turn that seed into a bounded route and explicit next handoff."
  else
    echo "3. Seed the packet before launching planner."
    echo
    echo "   scripts/seed_task_packet.sh $packet_path --goal \"...\" [--constraints \"...\"] [--dod \"...\"]"
    echo
    echo "4. Then launch planner:"
    echo
    echo "   scripts/start_next_role.sh --launch $packet_path"
  fi
  echo "5. Use the separate human report when you want the compact progress view:"
  echo
  echo "   ${report_path:-scripts/task_human_report.sh $packet_path}"
  echo
  echo "6. If you only want the prompt text instead:"
  echo
  echo "   scripts/render_handoff_brief.sh $packet_path planner"
  if [[ "$launch_mode" -eq 1 ]]; then
    echo
    if [[ "$seeded_value" == "yes" ]]; then
      echo "Launching planner now..."
    else
      echo "Launching planner now for interactive clarification on the blank draft packet..."
    fi
    exec "$repo_root/scripts/start_next_role.sh" --launch "$packet_path"
  fi
  exit 0
fi

mapfile -t packets < <(find_active_packets)
nonterminal_packets=()
orphan_reports=()
for packet in "${packets[@]}"; do
  if is_nonterminal_packet "$packet"; then
    nonterminal_packets+=("$packet")
  fi
done
mapfile -t orphan_reports < <(harness_list_orphan_human_reports "$repo_root" active)

echo "NaCC human bootstrap"
echo

if [[ "${#orphan_reports[@]}" -gt 0 ]]; then
  echo "Note:"
  echo "- Found ${#orphan_reports[@]} orphan active human report(s) with no matching packet."
  echo "- Run scripts/harness_audit.sh to inspect the stale report paths before assuming active state is fully clean."
  echo
fi

if [[ "${#packets[@]}" -gt 0 ]]; then
  show_active_packets
  if [[ "${#nonterminal_packets[@]}" -gt 0 ]]; then
    first_packet="${nonterminal_packets[0]}"
    echo "Recommended next move:"
    echo "- Keep the current nonterminal packet moving first:"
    echo "  $first_packet"
    if [[ "$(harness_extract_field "$first_packet" "Status")" == "draft" ]] && ! harness_packet_has_planner_seed "$first_packet"; then
      echo "- This packet is still waiting on the first human seed."
      echo "- You have two valid ways to continue:"
      echo
      echo "  1. Seed it directly from the shell:"
      echo
      echo "  scripts/seed_task_packet.sh $first_packet --goal \"...\" [--constraints \"...\"] [--dod \"...\"]"
      echo
      echo "  2. Or launch planner now and let planner collect the first seed interactively:"
      echo
      echo "  scripts/start_next_role.sh --launch $first_packet"
      echo
    else
      echo "- If you need a fresh role session, use:"
      echo
      echo "  scripts/start_next_role.sh --launch $first_packet"
      echo
    fi
    echo "- If you want the compact human-facing history first, use:"
    echo
    echo "  scripts/task_human_report.sh $first_packet"
    echo
    if [[ "$(count_active_packets_by_type planning)" -eq 0 ]]; then
      echo "Optional parallel move:"
      echo "- You do not currently have a planning packet."
      echo "- Create one in lane B if you want planner to shape the next step while the execution packet continues."
      echo "- You only need a rough next-step idea; planner can turn that into a bounded packet without reopening lane A:"
      echo
      echo "  scripts/spawn_next_planning_lane.sh $first_packet next_step_name \"rough next-step idea\""
      echo
    fi
  else
    echo "All packets in active/ are terminal."
    echo
    echo "Recommended next move:"
    echo "- Close or archive the finished packet(s) when convenient."
    echo "- Archive one explicitly with:"
    echo
    echo "  scripts/archive_task_packet.sh docs/workflow/tasks/active/<task>.md"
    echo
    echo "- Start the next round with either:"
    echo
    echo "  scripts/bootstrap_harness.sh --type execution task_name"
    echo "  scripts/bootstrap_harness.sh --type planning next_step_name"
    echo
  fi
  exit 0
fi

echo "No active task packets."
echo
show_pending_candidates
echo "Recommended next move:"
echo "- Pick one pending item."
echo "- Create one seeded packet with:"
echo
echo "  scripts/bootstrap_harness.sh --type execution <task_name> --goal \"...\" [--constraints \"...\"] [--dod \"...\"]"
echo
echo "- Or create the next-step planner lane directly with:"
echo
echo "  scripts/bootstrap_harness.sh --type planning <task_name>"
echo
echo "- If you create a blank packet intentionally, seed it before launching planner:"
echo
echo "  scripts/seed_task_packet.sh docs/workflow/tasks/active/<task>.md --goal \"...\""
