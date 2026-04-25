#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
packet="${1:-}"
source "$repo_root/scripts/harness_lib.sh"

if [[ -z "$packet" ]]; then
  echo "usage: scripts/harness_next.sh <task-packet-path>" >&2
  exit 1
fi

if [[ ! -f "$packet" ]]; then
  if [[ -f "$repo_root/$packet" ]]; then
    packet="$repo_root/$packet"
  else
    echo "task packet not found: $packet" >&2
    exit 1
  fi
fi

task_id="$(harness_task_id "$packet")"
lane="$(harness_extract_lane "$packet")"
packet_type="$(harness_extract_packet_type "$packet")"
status="$(harness_extract_field "$packet" "Status")"
owner="$(harness_extract_field "$packet" "Owner Role")"
goal="$(harness_extract_field "$packet" "Goal")"

echo "Task: ${task_id:-$(basename "$packet")}"
echo "Lane: ${lane:--}"
echo "Packet Type: ${packet_type:--}"
echo "Current owner: ${owner:--}"
echo "Status: ${status:--}"
echo "Goal: ${goal:--}"
echo

case "$status" in
  draft)
    if harness_packet_has_planner_seed "$packet"; then
      cat <<'EOF'
Recommended next owner: planner

Expected action:
- planner can now refine the seeded intent into a bounded route
- keep the packet as the source of truth
- write the next handoff explicitly before leaving planner
EOF
    else
      cat <<'EOF'
Recommended next owner: human

Expected action:
- add the first human seed directly into the packet
- recommended minimum: Goal
- optional if already known: Constraints / Definition Of Done / Scope
- helper:
  - `scripts/seed_task_packet.sh <task-packet> --goal "..." [--constraints "..."] [--dod "..."]`
EOF
    fi
    ;;
  in_progress)
    cat <<'EOF'
Recommended next owner: current owner

Expected action:
- keep working until there is either:
  - a reviewable artifact
  - or a blocker summary
- avoid handing off partial context without an artifact
EOF
    ;;
  needs_review)
    cat <<'EOF'
Recommended next owner: reviewer

Expected action:
- read the packet first
- inspect the patch / commit / changed files
- decide approve / approve-with-conditions / changes-requested / route-to-planner
- summarize the change for the human
EOF
    ;;
  changes_requested)
    cat <<'EOF'
Recommended next owner: coder

Expected action:
- address reviewer findings
- keep scope bounded to the packet
- return to needs_review when the artifact is ready again
EOF
    ;;
  needs_test)
    cat <<'EOF'
Recommended next owner: test_runner

Expected action:
- run the minimum validation tier requested by the packet
- report build actions, command run, outcome, and artifact paths
- if validation fails, move to test_failed
- if validation succeeds but the packet still needs evidence reduction or log interpretation, move to needs_analysis
- helper:
  - `scripts/request_post_run_analysis.sh <task-packet> --log <path>`
EOF
    ;;
  needs_analysis)
    cat <<'EOF'
Recommended next owner: log_analyzer

Expected action:
- compress the long log or trap evidence into a human-usable summary
- state whether the run looks acceptable, suspicious, or failed
- recommend whether the next hop is human, planner, or coder
EOF
    ;;
  test_failed)
    cat <<'EOF'
Recommended next owner: log_analyzer

Expected action:
- identify the first bad point
- separate symptom from likely cause
- recommend whether this returns to coder or planner
EOF
    ;;
  blocked)
    cat <<'EOF'
Recommended next owner: human or planner

Expected action:
- decide whether the blocker is local or architectural
- if local, narrow the packet and return ownership
- if architectural, route to planner and keep coding paused
EOF
    ;;
  done)
    cat <<'EOF'
Recommended next owner: human

Expected action:
- review the compressed artifact set
- decide merge / push / follow-up task
- move packet to completed when the round is closed
EOF
    ;;
  *)
    cat <<EOF
Unknown status: ${status:-<empty>}

Expected action:
- use one of:
  draft / in_progress / needs_review / changes_requested / needs_test / needs_analysis / test_failed / blocked / done
EOF
    ;;
esac
