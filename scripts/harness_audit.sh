#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/harness_lib.sh"

active_dir="$repo_root/docs/workflow/tasks/active"
error_count=0
warning_count=0

warn() {
  warning_count=$((warning_count + 1))
  printf 'WARN  %s\n' "$*"
}

fail() {
  error_count=$((error_count + 1))
  printf 'FAIL  %s\n' "$*"
}

check_required_field() {
  local file="$1"
  local label="$2"
  local value
  value="$(harness_extract_field "$file" "$label")"
  if [[ -z "$(harness_trim "$value")" ]]; then
    fail "$(basename "$file"): missing required field '$label'"
  fi
}

require_meaningful_field() {
  local file="$1"
  local label="$2"
  local task_label="$3"

  if ! harness_field_has_meaningful_value "$file" "$label"; then
    fail "$task_label: status-specific required field '$label' is missing"
  fi
}

warn_if_missing_field() {
  local file="$1"
  local label="$2"
  local task_label="$3"

  if ! harness_field_has_meaningful_value "$file" "$label"; then
    warn "$task_label: recommended field '$label' is missing"
  fi
}

report_has_role_entry() {
  local report_file="$1"
  local role="$2"

  [[ -f "$report_file" ]] || return 1
  rg -q "^## .* - ${role}\$" "$report_file"
}

if [[ ! -d "$active_dir" ]]; then
  echo "no active task directory: $active_dir"
  exit 0
fi

mapfile -t files < <(harness_sort_active_packets "$active_dir")
mapfile -t orphan_active_reports < <(harness_list_orphan_human_reports "$repo_root" active)

if [[ "${#files[@]}" -eq 0 ]]; then
  echo "no active task packets"
fi

for report in "${orphan_active_reports[@]}"; do
  warn "orphan active human report with no matching packet: $(harness_relative_path "$report" "$repo_root")"
done

for file in "${files[@]}"; do
  check_required_field "$file" "Task ID"
  check_required_field "$file" "Created"
  check_required_field "$file" "Lane"
  check_required_field "$file" "Packet Type"
  check_required_field "$file" "Status"
  check_required_field "$file" "Reconciliation Required"
  check_required_field "$file" "Post-Run Analysis Required"

  lane="$(harness_extract_lane "$file")"
  packet_type="$(harness_extract_packet_type "$file")"
  owner="$(harness_extract_field "$file" "Owner Role")"
  status="$(harness_extract_field "$file" "Status")"
  next_owner="$(harness_extract_next_owner "$file")"
  task_id="$(harness_task_id "$file")"
  reconciliation_required="$(harness_extract_field "$file" "Reconciliation Required")"
  post_run_analysis_required="$(harness_extract_field "$file" "Post-Run Analysis Required")"
  can_proceed_to_test="$(harness_extract_field "$file" "Can proceed to test")"
  packet_label="${task_id:-$(basename "$file")}"
  human_report="$(harness_human_report_path "$file" "$repo_root")"
  repair_output="$(harness_packet_handoff_repair "$file" || true)"
  is_blank_draft=0

  if [[ "$status" == "draft" ]] && ! harness_packet_has_planner_seed "$file"; then
    is_blank_draft=1
  fi

  case "$lane" in
    A|B|C) ;;
    *) fail "${task_id:-$(basename "$file")}: invalid lane '$lane'" ;;
  esac

  case "$packet_type" in
    execution|planning|analysis) ;;
    *) fail "${task_id:-$(basename "$file")}: invalid packet type '$packet_type'" ;;
  esac

  case "$owner" in
    "" )
      if [[ "$is_blank_draft" -eq 1 ]]; then
        warn "$packet_label: blank draft packet has no owner yet; seed it or set 'Owner Role: human'"
      else
        fail "${task_id:-$(basename "$file")}: invalid owner role '$owner'"
      fi
      ;;
    human|planner|coder|reviewer|test_runner|log_analyzer) ;;
    *) fail "${task_id:-$(basename "$file")}: invalid owner role '$owner'" ;;
  esac

  case "$status" in
    draft|in_progress|needs_review|changes_requested|needs_test|needs_analysis|test_failed|blocked|done) ;;
    *) fail "${task_id:-$(basename "$file")}: invalid status '$status'" ;;
  esac

  case "$next_owner" in
    ""|human|planner|coder|reviewer|test_runner|log_analyzer) ;;
    *) fail "${task_id:-$(basename "$file")}: invalid next owner '$next_owner'" ;;
  esac

  case "$packet_type:$lane" in
    execution:A|planning:B|analysis:C) ;;
    *)
      warn "${packet_label}: packet type '$packet_type' usually belongs to lane '$(
        case "$packet_type" in
          execution) printf 'A' ;;
          planning) printf 'B' ;;
          analysis) printf 'C' ;;
          *) printf '?' ;;
        esac
      )', found '$lane'"
      ;;
  esac

  if [[ ! -f "$human_report" ]]; then
    warn "$packet_label: human report file is missing ($human_report)"
  fi

  if ! harness_field_has_meaningful_value "$file" "Priority"; then
    if [[ "$is_blank_draft" -eq 1 ]]; then
      warn "$packet_label: blank draft packet has no priority yet"
    else
      warn "$packet_label: recommended field 'Priority' is missing"
    fi
  fi

  if ! harness_field_has_meaningful_value "$file" "Goal"; then
    if [[ "$is_blank_draft" -eq 1 ]]; then
      warn "$packet_label: blank draft packet is still missing the first human seed ('Goal')"
    else
      fail "$packet_label: status-specific required field 'Goal' is missing"
    fi
  fi

  if [[ -n "$repair_output" ]]; then
    IFS=$'\t' read -r repair_role repair_reason <<< "$repair_output"
    fail "$packet_label: $repair_reason (repair owner: ${repair_role:-unknown})"
  fi

  case "$status" in
    needs_review)
      warn_if_missing_field "$file" "Implementation summary" "$packet_label"
      if ! harness_field_has_meaningful_value "$file" "Commit or patch" && ! harness_field_has_meaningful_value "$file" "Patch or commit"; then
        warn "$packet_label: review handoff has no concrete patch/commit artifact recorded yet"
      fi
      if [[ -f "$human_report" ]] && ! report_has_role_entry "$human_report" "coder"; then
        warn "$packet_label: coder result exists but human report has no 'coder' entry yet"
      fi
      ;;
    needs_test)
      require_meaningful_field "$file" "Approval status" "$packet_label"
      require_meaningful_field "$file" "Spec fidelity" "$packet_label"
      require_meaningful_field "$file" "Risk review" "$packet_label"
      if [[ "$can_proceed_to_test" != "yes" ]]; then
        fail "$packet_label: status needs_test requires 'Can proceed to test: yes'"
      fi
      warn_if_missing_field "$file" "Key files reviewed" "$packet_label"
      warn_if_missing_field "$file" "Human-facing code explanation" "$packet_label"
      warn_if_missing_field "$file" "Why this route still fits the packet" "$packet_label"
      if [[ -f "$human_report" ]] && ! report_has_role_entry "$human_report" "reviewer"; then
        warn "$packet_label: reviewer result exists but human report has no 'reviewer' entry yet"
      fi
      if [[ -n "$next_owner" && "$next_owner" != "test_runner" ]]; then
        warn "$packet_label: status needs_test usually expects 'Next owner: test_runner', found '$next_owner'"
      fi
      ;;
    needs_analysis)
      if [[ "$post_run_analysis_required" != "yes" ]]; then
        fail "$packet_label: status needs_analysis requires 'Post-Run Analysis Required: yes'"
      fi
      if ! harness_field_has_meaningful_value "$file" "Primary log path" && ! harness_field_has_meaningful_value "$file" "Artifact / log path"; then
        fail "$packet_label: status needs_analysis requires a primary or test-result log path"
      fi
      if [[ -n "$next_owner" && "$next_owner" != "log_analyzer" ]]; then
        warn "$packet_label: status needs_analysis usually expects 'Next owner: log_analyzer', found '$next_owner'"
      fi
      ;;
    test_failed)
      if ! harness_field_has_meaningful_value "$file" "Primary log path" && ! harness_field_has_meaningful_value "$file" "Artifact / log path"; then
        fail "$packet_label: status test_failed requires a primary or test-result log path"
      fi
      if [[ -n "$next_owner" && "$next_owner" != "log_analyzer" ]]; then
        warn "$packet_label: status test_failed usually expects 'Next owner: log_analyzer', found '$next_owner'"
      fi
      ;;
    done)
      if [[ "$post_run_analysis_required" == "yes" ]]; then
        warn "$packet_label: packet is marked done while post-run analysis is still required"
      fi
      if [[ "$reconciliation_required" == "yes" ]]; then
        warn "$packet_label: packet is marked done while reconciliation is still required"
      fi
      if [[ "$packet_type" != "planning" ]] && \
         ! harness_field_has_meaningful_value "$file" "Outcome" && \
         ! harness_field_has_meaningful_value "$file" "Human-facing summary" && \
         ! harness_field_has_meaningful_value "$file" "Verdict" && \
         ! harness_field_has_meaningful_value "$file" "Run verdict" && \
         ! { [[ -f "$human_report" ]] && { \
              report_has_role_entry "$human_report" "coder" || \
              report_has_role_entry "$human_report" "reviewer" || \
              report_has_role_entry "$human_report" "log_analyzer"; \
            }; }; then
        warn "$packet_label: terminal non-planning packet has no recorded test outcome or analysis summary"
      fi
      if harness_field_has_meaningful_value "$file" "Implementation summary" && [[ -f "$human_report" ]] && ! report_has_role_entry "$human_report" "coder"; then
        warn "$packet_label: coder result is present but human report has no 'coder' entry yet"
      fi
      if harness_field_has_meaningful_value "$file" "Approval status" && [[ -f "$human_report" ]] && ! report_has_role_entry "$human_report" "reviewer"; then
        warn "$packet_label: reviewer result is present but human report has no 'reviewer' entry yet"
      fi
      if harness_field_has_meaningful_value "$file" "Observed symptom" && [[ -f "$human_report" ]] && ! report_has_role_entry "$human_report" "log_analyzer"; then
        warn "$packet_label: analysis result is present but human report has no 'log_analyzer' entry yet"
      fi
      ;;
  esac

  if [[ "$status" == "done" ]]; then
    warn "${packet_label}: terminal packet still lives under active/; archive it when convenient"
  fi
done

echo
echo "Harness audit summary:"
echo "- packets checked: ${#files[@]}"
echo "- orphan active reports: ${#orphan_active_reports[@]}"
echo "- warnings: $warning_count"
echo "- errors: $error_count"

if [[ "$error_count" -ne 0 ]]; then
  exit 1
fi
