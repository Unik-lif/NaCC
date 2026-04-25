#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/harness_lib.sh"
packet="${1:-}"
packet_arg="$packet"
role="${2:-}"

if [[ -z "$packet" || -z "$role" ]]; then
  echo "usage: scripts/render_handoff_brief.sh <task-packet-path> <role>" >&2
  exit 1
fi

packet="$(harness_resolve_packet_path "$packet" "$repo_root" || true)"
if [[ -z "$packet" ]]; then
  echo "task packet not found: $packet_arg" >&2
  exit 1
fi

extract_section() {
  local header="$1"
  local next_header="$2"
  awk -v start="$header" -v stop="$next_header" '
    $0 == start { in_section=1; next }
    $0 == stop { in_section=0 }
    in_section { print }
  ' "$packet"
}

task_id="$(harness_extract_field "$packet" "Task ID")"
priority="$(harness_extract_field "$packet" "Priority")"
lane="$(harness_extract_field "$packet" "Lane")"
packet_type="$(harness_extract_field "$packet" "Packet Type")"
status="$(harness_extract_field "$packet" "Status")"
goal="$(harness_extract_field "$packet" "Goal")"
critical_intent="$(harness_extract_field "$packet" "Critical Intent")"
preferred_shape="$(harness_extract_field "$packet" "Preferred Shape")"
disallowed_shape="$(harness_extract_field "$packet" "Disallowed Shape")"
allowed_freedom="$(harness_extract_field "$packet" "Allowed Freedom")"
scope="$(harness_extract_field "$packet" "Scope")"
constraints="$(harness_extract_field "$packet" "Constraints")"
open_semantic_questions="$(harness_extract_field "$packet" "Open Semantic Questions")"
human_concern="$(harness_extract_field "$packet" "Human Concern")"
key_assumptions="$(harness_extract_field "$packet" "Key Assumptions")"
evidence_boundary="$(harness_extract_field "$packet" "Evidence / Inference Boundary")"
reconciliation_required="$(harness_extract_field "$packet" "Reconciliation Required")"
post_run_analysis_required="$(harness_extract_field "$packet" "Post-Run Analysis Required")"
dod="$(harness_extract_field "$packet" "Definition Of Done")"
validation_tier="$(harness_extract_field "$packet" "Validation Tier")"
human_report_path="$(harness_ensure_human_report "$packet" "$repo_root")"
human_report_rel="$(harness_relative_path "$human_report_path" "$repo_root")"

latest_summary="$(extract_section "## Latest Summary" "## Next Handoff" | sed '/^[[:space:]]*$/d')"
next_handoff="$(extract_section "## Next Handoff" "## Coder Result" | sed '/^[[:space:]]*$/d')"
coder_result="$(extract_section "## Coder Result" "## Review Result" | sed '/^[[:space:]]*$/d')"
review_result="$(extract_section "## Review Result" "## Test Result" | sed '/^[[:space:]]*$/d')"
test_result="$(extract_section "## Test Result" "## Analysis Result" | sed '/^[[:space:]]*$/d')"
analysis_result="$(extract_section "## Analysis Result" "## Open Questions" | sed '/^[[:space:]]*$/d')"

case "$role" in
  planner)
    read_first=$'- task packet\n- docs/workflow/CURRENT_STATE.md\n- docs/workflow/HYPOTHESES.md\n- docs/workflow/NEXT_STEPS.md'
    role_focus='Decide route, dependencies, and packet semantics. Tighten intent and route constraints enough that execution does not need to invent meaning-level assumptions, and write remaining ambiguities down explicitly instead of choosing one silently. Treat `CURRENT_STATE.md`, `HYPOTHESES.md`, and `NEXT_STEPS.md` as auxiliary project context: use them to detect conflicts, falsified paths, and relevant project-wide constraints, but do not let them override the current human seed or the packet''s local intent.'
    report_contract=$'- human report updates are optional for planner in this version\n- if you add one anyway, keep it short and do not rewrite older entries'
    packet_gate=$'- if you set a machine next owner, fill `Trigger`, `Exact task for next owner`, `Expected deliverable`, `Stop condition`, and `Do not do in this turn`\n- for non-planner next owners, also fill `Exact artifact to read first`\n- if multiple plausible interpretations remain, write them into `Open Semantic Questions` instead of silently freezing one\n- if project-level state files conflict with the fresh human seed, record that conflict explicitly instead of silently letting the older project context win\n- if reconciliation is still open, keep `Reconciliation Required: yes` instead of pretending the route is frozen'
    ;;
  coder)
    read_first=$'- task packet\n- docs/workflow/CURRENT_STATE.md\n- related ticket or plan if listed in the packet\n- exact artifact from Next Handoff'
    role_focus='Implement only the bounded change, prefer the least invasive allowed route, prefer the smallest sufficient diff, and escalate instead of guessing when packet semantics are insufficient. The intended flow is coder -> reviewer -> test_runner. Stop after code plus cheap bounded sanity; do not try to close the whole compile/run proof loop inside one coder session.'
    report_contract=$'- append a new timestamped `coder` section to the human report\n- explain what changed, which files carry the change, why it was needed, what was intentionally left unchanged, which cheap sanity checks were run, and what was intentionally deferred to reviewer / test_runner\n- do not rewrite or collapse older report entries'
    packet_gate=$'- before reviewer handoff, leave a meaningful `Implementation summary` or `Commit or patch`\n- if the change relies on a nontrivial assumption, write it into the packet or human report explicitly instead of leaving it implicit in code\n- fill the `Next Handoff` block concretely so reviewer can start fresh from the packet\n- if the route became ambiguous, stop and leave the packet in a planner-facing state instead of half-filling reviewer handoff\n- do not default to `make linux-update`, `make opensbi`, `make qemu`, full image rebuilds, tmux debug loops, or VM/QEMU proof unless the packet explicitly assigns coder-owned proof for this slice\n- if heavy proof is still needed, say so explicitly and defer it to reviewer / test_runner instead of spending the coder session trying to finish the whole packet'
    ;;
  reviewer)
    read_first=$'- task packet\n- docs/workflow/CURRENT_STATE.md\n- patch / commit / changed files\n- minimal validation artifacts if they exist'
    role_focus='Run the spec-fidelity gate first, then the risk gate. Decide whether the patch faithfully implemented the packet intent before allowing it to move to test, and treat silent assumption jumps or avoidable overbuilding as fidelity problems.'
    report_contract=$'- append a new timestamped `reviewer` section to the human report\n- state the review verdict, what you checked directly, the most important findings, a short plain-English code explanation, and what the human should watch next\n- do not rewrite or collapse older report entries'
    packet_gate=$'- before coder or test-runner handoff, fill `Approval status`, `Spec fidelity`, and `Risk review`\n- if moving to test, `Can proceed to test` must be exactly `yes`\n- if moving to test, `Validation Tier`, `Test command or batch plan`, and `Key Assumptions` must already be explicit in the packet\n- fill the `Next Handoff` block concretely so the next role can start fresh without chat history'
    ;;
  test_runner)
    read_first=$'- task packet\n- docs/workflow/CURRENT_STATE.md\n- docs/workflow/AGENT_TEST_RUNNER.md\n- exact command or batch plan from the packet'
    role_focus='Run the requested validation tier and report only execution status plus artifact paths.'
    report_contract=$'- test_runner does not own the human report by default in this version\n- keep the packet focused on execution status and artifact paths'
    packet_gate=$'- do not invent validation scope: if `Validation Tier` or `Test command or batch plan` is missing, stop and route back\n- before `log_analyzer` handoff, record `Primary log path` or `Artifact / log path`\n- if the run needs evidence reduction, set `Status: needs_analysis` and fill the `Next Handoff` block with the exact artifact and question for log_analyzer\n- do not leave long-log interpretation implied'
    ;;
  log_analyzer)
    read_first=$'- task packet\n- docs/workflow/CURRENT_STATE.md\n- experiment or test result in the packet\n- primary log path or failing log path'
    role_focus='Compress long logs into evidence, verdict, and next-step guidance. This role is for successful-but-long runs too, not only failures. Keep observed evidence separate from your inference.'
    report_contract=$'- append a new timestamped `log_analyzer` section to the human report\n- summarize the run verdict, dominant signal, key evidence or log paths, what the result means for the next decision, and what remains uncertain\n- do not rewrite or collapse older report entries'
    packet_gate=$'- write a concrete `Verdict`, `Human-facing summary`, `Evidence / Inference Boundary`, `Recommended next owner`, and `Recommended next step`\n- if handing to coder or planner, fill the `Next Handoff` block concretely instead of only naming the next owner\n- avoid appending near-duplicate analysis turns once the verdict is already stable'
    ;;
  human)
    read_first=$'- task packet\n- latest summary\n- review / test / analysis sections as needed'
    role_focus='Make the judgment call, not the first-pass reconstruction.'
    report_contract=$'- read the human report first if you want a compact cumulative view before opening the raw packet diff'
    ;;
  *)
    echo "unsupported role: $role" >&2
    echo "supported roles: planner coder reviewer test_runner log_analyzer human" >&2
    exit 1
    ;;
esac

cat <<EOF
# NaCC Handoff Brief

Role: $role
Task Packet: $packet

## Snapshot

- Task ID: ${task_id:--}
- Priority: ${priority:--}
- Lane: ${lane:--}
- Packet Type: ${packet_type:--}
- Status: ${status:--}
- Goal: ${goal:--}
- Critical Intent: ${critical_intent:--}
- Preferred Shape: ${preferred_shape:--}
- Disallowed Shape: ${disallowed_shape:--}
- Allowed Freedom: ${allowed_freedom:--}
- Scope: ${scope:--}
- Constraints: ${constraints:--}
- Open Semantic Questions: ${open_semantic_questions:--}
- Human Concern: ${human_concern:--}
- Key Assumptions: ${key_assumptions:--}
- Evidence / Inference Boundary: ${evidence_boundary:--}
- Reconciliation Required: ${reconciliation_required:--}
- Post-Run Analysis Required: ${post_run_analysis_required:--}
- Definition Of Done: ${dod:--}
- Validation Tier: ${validation_tier:--}

## Read First

$read_first

## Role Focus

$role_focus

## Human Report

- Report file: ${human_report_rel:--}
- Append rule: add a new timestamped section for your turn; do not rewrite older entries
- Role-specific requirements:
$report_contract

## Packet Handoff Gate

$packet_gate

## Latest Summary

${latest_summary:--}

## Next Handoff

${next_handoff:--}

## Coder Result

${coder_result:--}

## Review Result

${review_result:--}

## Test Result

${test_result:--}

## Analysis Result

${analysis_result:--}

## Session Rule

- Prefer solving this from repository state and packet artifacts, not prior chat history.
- Open the task packet file itself and do not rely only on this generated summary.
- If the packet is stale, update the packet first instead of growing the session context.
- If a key assumption, validation target, or semantic choice is missing, surface the gap explicitly instead of silently inventing it.
EOF
