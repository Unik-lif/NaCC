#!/usr/bin/env bash

if [[ -n "${NACC_HARNESS_LIB_SOURCED:-}" ]]; then
  return 0
fi
NACC_HARNESS_LIB_SOURCED=1

harness_repo_root() {
  local src_dir
  src_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "$src_dir/.." && pwd
}

harness_resolve_packet_path() {
  local packet="$1"
  local repo_root="$2"
  local resolved=""

  if [[ -f "$packet" ]]; then
    resolved="$packet"
  elif [[ -f "$repo_root/$packet" ]]; then
    resolved="$repo_root/$packet"
  else
    return 1
  fi

  if [[ "$resolved" != /* ]]; then
    resolved="$repo_root/$resolved"
  fi

  if [[ "$resolved" != "$repo_root/"* ]]; then
    resolved="$(cd "$(dirname "$resolved")" && pwd)/$(basename "$resolved")"
  else
    resolved="$repo_root/${resolved#$repo_root/}"
  fi

  if [[ -f "$resolved" ]]; then
    printf '%s\n' "$resolved"
    return 0
  fi

  return 1
}

harness_relative_path() {
  local path="$1"
  local repo_root="$2"

  case "$path" in
    "$repo_root"/*)
      printf '%s\n' "${path#$repo_root/}"
      ;;
    *)
      printf '%s\n' "$path"
      ;;
  esac
}

harness_extract_field() {
  local file="$1"
  local label="$2"
  awk -v key="$label" '
    index($0, "- " key ":") == 1 {
      sub("^- " key ":[[:space:]]*", "", $0)
      print
      exit
    }
  ' "$file"
}

harness_extract_next_owner() {
  local file="$1"
  awk '
    index($0, "- Next owner:") == 1 {
      sub("^- Next owner:[[:space:]]*", "", $0)
      print
      exit
    }
  ' "$file"
}

harness_first_meaningful_field() {
  local file="$1"
  shift
  local label

  for label in "$@"; do
    if harness_field_has_meaningful_value "$file" "$label"; then
      printf '%s\n' "$label"
      return 0
    fi
  done

  return 1
}

harness_first_missing_field() {
  local file="$1"
  shift
  local label

  for label in "$@"; do
    if ! harness_field_has_meaningful_value "$file" "$label"; then
      printf '%s\n' "$label"
      return 0
    fi
  done

  return 1
}

harness_trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s\n' "$value"
}

harness_has_meaningful_value() {
  local value
  value="$(harness_trim "${1:-}")"
  [[ -n "$value" && "$value" != "-" && "$value" != "no" && "$value" != "No" ]]
}

harness_field_has_meaningful_value() {
  local file="$1"
  local label="$2"
  local value

  value="$(harness_extract_field "$file" "$label")"
  if harness_has_meaningful_value "$value"; then
    return 0
  fi

  value="$(
    awk -v key="$label" '
      index($0, "- " key ":") == 1 {
        in_block=1
        next
      }

      in_block {
        if ($0 ~ /^- [^[:space:]].*:/ || $0 ~ /^##[[:space:]]/) {
          exit
        }

        if ($0 ~ /^[[:space:]]*$/) {
          next
        }

        candidate=$0
        sub(/^[[:space:]]+/, "", candidate)
        print candidate
        exit
      }
    ' "$file"
  )"

  harness_has_meaningful_value "$value"
}

harness_set_field() {
  local file="$1"
  local label="$2"
  local value="$3"

  HARNESS_LABEL="$label" HARNESS_VALUE="$value" perl -0pi -e '
    BEGIN {
      $label = $ENV{HARNESS_LABEL};
      $value = $ENV{HARNESS_VALUE};
      $changed = 0;
    }
    $changed = s/^- \Q$label\E:[^\n]*$/- $label: $value/m;
    END {
      exit($changed ? 0 : 2);
    }
  ' "$file"
}

harness_is_supported_role() {
  case "$1" in
    planner|coder|reviewer|test_runner|log_analyzer) return 0 ;;
    *) return 1 ;;
  esac
}

harness_priority_rank() {
  case "$1" in
    P0) printf '0\n' ;;
    P1) printf '1\n' ;;
    P2) printf '2\n' ;;
    P3) printf '3\n' ;;
    *) printf '9\n' ;;
  esac
}

harness_lane_rank() {
  case "$1" in
    A) printf '0\n' ;;
    B) printf '1\n' ;;
    C) printf '2\n' ;;
    *) printf '9\n' ;;
  esac
}

harness_packet_type_rank() {
  case "$1" in
    execution) printf '0\n' ;;
    planning) printf '1\n' ;;
    analysis) printf '2\n' ;;
    *) printf '9\n' ;;
  esac
}

harness_handoff_writer_role_for_status() {
  local status="$1"
  local owner="${2:-}"

  case "$status" in
    needs_review)
      printf 'coder\n'
      ;;
    changes_requested|needs_test)
      printf 'reviewer\n'
      ;;
    needs_analysis|test_failed)
      printf 'test_runner\n'
      ;;
    *)
      if harness_is_supported_role "$owner"; then
        printf '%s\n' "$owner"
      else
        return 1
      fi
      ;;
  esac
}

harness_packet_source_role_for_dispatch() {
  local file="$1"
  local target_role="$2"
  local status owner source_role

  status="$(harness_extract_field "$file" "Status")"
  owner="$(harness_extract_field "$file" "Owner Role")"
  source_role="$(harness_handoff_writer_role_for_status "$status" "$owner" || true)"
  if ! harness_is_supported_role "$source_role"; then
    return 1
  fi

  if [[ "$source_role" == "$target_role" ]]; then
    return 1
  fi

  printf '%s\n' "$source_role"
}

harness_machine_handoff_missing_field() {
  local file="$1"
  local next_owner="$2"
  local missing=""

  if ! harness_is_supported_role "$next_owner" || [[ "$next_owner" == "human" ]]; then
    return 1
  fi

  missing="$(harness_first_missing_field "$file" \
    "Trigger" \
    "Exact task for next owner" \
    "Expected deliverable" \
    "Stop condition" \
    "Do not do in this turn" || true)"
  if [[ -n "$missing" ]]; then
    printf '%s\n' "$missing"
    return 0
  fi

  if [[ "$next_owner" != "planner" ]]; then
    missing="$(harness_first_missing_field "$file" "Exact artifact to read first" || true)"
    if [[ -n "$missing" ]]; then
      printf '%s\n' "$missing"
      return 0
    fi
  fi

  if [[ "$next_owner" != "planner" ]]; then
    missing="$(harness_first_missing_field "$file" "Key Assumptions" || true)"
    if [[ -n "$missing" ]]; then
      printf '%s\n' "$missing"
      return 0
    fi
  fi

  return 1
}

harness_analysis_handoff_missing_field() {
  local file="$1"
  local owner="$2"
  local status="$3"
  local missing=""

  [[ "$owner" == "log_analyzer" ]] || return 1

  case "$status" in
    needs_analysis|test_failed)
      return 1
      ;;
  esac

  if ! harness_first_meaningful_field "$file" \
    "Verdict" \
    "Human-facing summary" \
    "Recommended next owner" \
    "Recommended next step" >/dev/null 2>&1; then
    return 1
  fi

  missing="$(harness_first_missing_field "$file" \
    "Verdict" \
    "Human-facing summary" \
    "Evidence / Inference Boundary" \
    "Recommended next owner" \
    "Recommended next step" || true)"
  if [[ -n "$missing" ]]; then
    printf '%s\n' "$missing"
    return 0
  fi

  return 1
}

harness_packet_handoff_repair() {
  local file="$1"
  local status owner next_owner can_proceed_to_test writer_role missing=""

  status="$(harness_extract_field "$file" "Status")"
  owner="$(harness_extract_field "$file" "Owner Role")"
  next_owner="$(harness_extract_next_owner "$file")"
  can_proceed_to_test="$(harness_extract_field "$file" "Can proceed to test")"
  writer_role="$(harness_handoff_writer_role_for_status "$status" "$owner" || true)"

  case "$status" in
    needs_review)
      if ! harness_first_meaningful_field "$file" "Implementation summary" "Commit or patch" "Patch or commit" >/dev/null 2>&1; then
        if [[ -n "$writer_role" ]]; then
          printf '%s\t%s\n' "$writer_role" "review handoff incomplete: missing implementation artifact"
          return 0
        fi
      fi
      ;;
    changes_requested)
      missing="$(harness_first_missing_field "$file" \
        "Approval status" \
        "Spec fidelity" \
        "Risk review" || true)"
      if [[ -n "$missing" && -n "$writer_role" ]]; then
        printf '%s\t%s\n' "$writer_role" "changes-requested handoff incomplete: missing '$missing'"
        return 0
      fi
      ;;
    needs_test)
      missing="$(harness_first_missing_field "$file" \
        "Approval status" \
        "Spec fidelity" \
        "Risk review" || true)"
      if [[ -n "$missing" && -n "$writer_role" ]]; then
        printf '%s\t%s\n' "$writer_role" "test handoff incomplete: missing '$missing'"
        return 0
      fi
      if [[ "$can_proceed_to_test" != "yes" && -n "$writer_role" ]]; then
        printf '%s\t%s\n' "$writer_role" "test handoff incomplete: reviewer gate is not 'Can proceed to test: yes'"
        return 0
      fi
      missing="$(harness_first_missing_field "$file" \
        "Validation Tier" \
        "Test command or batch plan" || true)"
      if [[ -n "$missing" && -n "$writer_role" ]]; then
        printf '%s\t%s\n' "$writer_role" "test handoff incomplete: missing '$missing'"
        return 0
      fi
      ;;
    needs_analysis|test_failed)
      if ! harness_first_meaningful_field "$file" "Primary log path" "Artifact / log path" >/dev/null 2>&1; then
        if [[ -n "$writer_role" ]]; then
          printf '%s\t%s\n' "$writer_role" "analysis handoff incomplete: missing primary log path"
          return 0
        fi
      fi
      ;;
  esac

  missing="$(harness_analysis_handoff_missing_field "$file" "$owner" "$status" || true)"
  if [[ -n "$missing" && -n "$writer_role" ]]; then
    printf '%s\t%s\n' "$writer_role" "analysis handoff incomplete: missing '$missing'"
    return 0
  fi

  missing="$(harness_machine_handoff_missing_field "$file" "$next_owner" || true)"
  if [[ -n "$missing" && -n "$writer_role" ]]; then
    printf '%s\t%s\n' "$writer_role" "machine handoff incomplete: missing '$missing'"
    return 0
  fi

  return 1
}

harness_extract_lane() {
  harness_extract_field "$1" "Lane"
}

harness_extract_packet_type() {
  harness_extract_field "$1" "Packet Type"
}

harness_infer_next_role() {
  local file="$1"
  local status owner next_owner reconciliation_required repair_output repair_role repair_reason
  local role="" reason="" action_state="no-action"

  status="$(harness_extract_field "$file" "Status")"
  owner="$(harness_extract_field "$file" "Owner Role")"
  next_owner="$(harness_extract_next_owner "$file")"
  reconciliation_required="$(harness_extract_field "$file" "Reconciliation Required")"

  if [[ "$status" == "done" ]]; then
    reason="done packet should be archived before follow-on work"
    action_state="waiting-human"
  elif [[ "$reconciliation_required" == "yes" ]]; then
    role="planner"
    reason="packet requires reconciliation"
    action_state="dispatch"
  else
    repair_output="$(harness_packet_handoff_repair "$file" || true)"
    if [[ -n "$repair_output" ]]; then
      IFS=$'\t' read -r repair_role repair_reason <<< "$repair_output"
      role="$repair_role"
      reason="$repair_reason"
      action_state="dispatch"
    elif harness_packet_waits_for_human_checkpoint "$file"; then
      reason="machine handoff held for human checkpoint"
      action_state="waiting-human"
    elif harness_is_supported_role "$next_owner"; then
      role="$next_owner"
      reason="explicit Next owner field"
      action_state="dispatch"
    else
      case "$status" in
        draft)
          if harness_packet_has_planner_seed "$file"; then
            role="planner"
            reason="draft packet has human seed"
            action_state="dispatch"
          else
            reason="draft packet still needs human seed"
            action_state="waiting-human"
          fi
          ;;
        in_progress)
          if harness_is_supported_role "$owner"; then
            role="$owner"
            reason="status in_progress uses current owner"
            action_state="dispatch"
          else
            reason="in_progress but no supported current owner"
            action_state="waiting-human"
          fi
          ;;
        needs_review)
          role="reviewer"
          reason="status needs_review"
          action_state="dispatch"
          ;;
        changes_requested)
          role="coder"
          reason="status changes_requested"
          action_state="dispatch"
          ;;
        needs_test)
          role="test_runner"
          reason="status needs_test"
          action_state="dispatch"
          ;;
        needs_analysis)
          role="log_analyzer"
          reason="status needs_analysis"
          action_state="dispatch"
          ;;
        test_failed)
          role="log_analyzer"
          reason="status test_failed"
          action_state="dispatch"
          ;;
        blocked)
          role="planner"
          reason="status blocked defaults to planner"
          action_state="dispatch"
          ;;
        *)
          reason="unknown or unsupported status"
          action_state="waiting-human"
          ;;
      esac
    fi
  fi

  printf '%s\t%s\t%s\n' "$role" "$reason" "$action_state"
}

harness_dispatch_signature() {
  local file="$1"
  local role="$2"
  local status owner next_owner reconciliation_required can_proceed_to_test spec_fidelity
  local primary_log_path artifact_log_path trigger exact_artifact exact_task expected_deliverable stop_condition do_not_do

  status="$(harness_extract_field "$file" "Status")"
  owner="$(harness_extract_field "$file" "Owner Role")"
  next_owner="$(harness_extract_next_owner "$file")"
  reconciliation_required="$(harness_extract_field "$file" "Reconciliation Required")"
  can_proceed_to_test="$(harness_extract_field "$file" "Can proceed to test")"
  spec_fidelity="$(harness_extract_field "$file" "Spec fidelity")"
  primary_log_path="$(harness_extract_field "$file" "Primary log path")"
  artifact_log_path="$(harness_extract_field "$file" "Artifact / log path")"
  trigger="$(harness_extract_field "$file" "Trigger")"
  exact_artifact="$(harness_extract_field "$file" "Exact artifact to read first")"
  exact_task="$(harness_extract_field "$file" "Exact task for next owner")"
  expected_deliverable="$(harness_extract_field "$file" "Expected deliverable")"
  stop_condition="$(harness_extract_field "$file" "Stop condition")"
  do_not_do="$(harness_extract_field "$file" "Do not do in this turn")"

  printf '%s' "$role|$status|$owner|$next_owner|$reconciliation_required|$can_proceed_to_test|$spec_fidelity|$primary_log_path|$artifact_log_path|$trigger|$exact_artifact|$exact_task|$expected_deliverable|$stop_condition|$do_not_do" | sha1sum | awk '{print $1}'
}

harness_packet_has_planner_seed() {
  local file="$1"

  harness_first_meaningful_field "$file" \
    "Goal" \
    "Critical Intent" \
    "Scope" \
    "Constraints" \
    "Definition Of Done" \
    "Open Semantic Questions" \
    "Human Concern" >/dev/null 2>&1
}

harness_packet_waits_for_human_checkpoint() {
  local file="$1"
  local checkpoint next_owner

  checkpoint="$(harness_extract_field "$file" "Human Checkpoint Required")"
  next_owner="$(harness_extract_next_owner "$file")"

  [[ "$checkpoint" == "yes" ]] || return 1
  [[ "$next_owner" == "human" ]]
}

harness_packet_checkpoint_target_role() {
  local file="$1"
  local status next_owner

  next_owner="$(harness_extract_next_owner "$file")"
  if harness_is_supported_role "$next_owner"; then
    printf '%s\n' "$next_owner"
    return 0
  fi

  status="$(harness_extract_field "$file" "Status")"
  case "$status" in
    needs_review)
      printf 'reviewer\n'
      ;;
    changes_requested)
      printf 'coder\n'
      ;;
    needs_test)
      printf 'test_runner\n'
      ;;
    needs_analysis|test_failed)
      printf 'log_analyzer\n'
      ;;
    blocked)
      printf 'planner\n'
      ;;
    *)
      return 1
      ;;
  esac
}

harness_packet_waits_for_human_seed_after_dispatch() {
  local file="$1"
  local role="$2"
  local status

  [[ "$role" == "planner" ]] || return 1

  status="$(harness_extract_field "$file" "Status")"
  [[ "$status" == "draft" ]] || return 1

  if harness_packet_has_planner_seed "$file"; then
    return 1
  fi

  return 0
}

harness_task_id() {
  harness_extract_field "$1" "Task ID"
}

harness_human_report_state_for_packet() {
  local packet="$1"
  local repo_root="$2"

  case "$packet" in
    "$repo_root"/docs/workflow/tasks/completed/*)
      printf 'completed\n'
      ;;
    *)
      printf 'active\n'
      ;;
  esac
}

harness_human_report_dir_for_state() {
  local repo_root="$1"
  local state="$2"

  printf '%s/docs/workflow/tasks/reports/%s\n' "$repo_root" "$state"
}

harness_task_packet_dir_for_state() {
  local repo_root="$1"
  local state="$2"

  printf '%s/docs/workflow/tasks/%s\n' "$repo_root" "$state"
}

harness_task_packet_path_for_task_id() {
  local repo_root="$1"
  local state="$2"
  local task_id="$3"

  printf '%s/%s.md\n' \
    "$(harness_task_packet_dir_for_state "$repo_root" "$state")" \
    "$task_id"
}

harness_human_report_path_for_task_id() {
  local repo_root="$1"
  local state="$2"
  local task_id="$3"

  printf '%s/%s_human_report.md\n' \
    "$(harness_human_report_dir_for_state "$repo_root" "$state")" \
    "$task_id"
}

harness_human_report_path() {
  local packet="$1"
  local repo_root="$2"
  local task_id state

  task_id="$(harness_task_id "$packet")"
  state="$(harness_human_report_state_for_packet "$packet" "$repo_root")"
  harness_human_report_path_for_task_id "$repo_root" "$state" "$task_id"
}

harness_ensure_human_report() {
  local packet="$1"
  local repo_root="$2"
  local report_path report_dir task_id packet_rel created

  task_id="$(harness_task_id "$packet")"
  report_path="$(harness_human_report_path "$packet" "$repo_root")"
  report_dir="$(dirname "$report_path")"
  packet_rel="$(harness_relative_path "$packet" "$repo_root")"
  created="$(date '+%Y-%m-%d %H:%M:%S %z')"

  mkdir -p "$report_dir"

  if [[ ! -f "$report_path" ]]; then
    cat >"$report_path" <<EOF
# Human Progress Report

- Task ID: ${task_id:--}
- Task Packet: \`${packet_rel}\`
- Created: ${created}
- Purpose: cumulative human-readable updates appended by coder, reviewer, and log_analyzer
- Append Rule: add a new timestamped section for each new turn; do not rewrite older entries
- Reading Hint: newest updates are appended at the end of this file

EOF
  fi

  printf '%s\n' "$report_path"
}

harness_human_report_task_id_from_path() {
  local report_path="$1"

  basename "$report_path" _human_report.md
}

harness_list_orphan_human_reports() {
  local repo_root="$1"
  local state="${2:-active}"
  local report_dir report_path task_id packet_path

  report_dir="$(harness_human_report_dir_for_state "$repo_root" "$state")"
  [[ -d "$report_dir" ]] || return 0

  while IFS= read -r -d '' report_path; do
    task_id="$(harness_human_report_task_id_from_path "$report_path")"
    packet_path="$(harness_task_packet_path_for_task_id "$repo_root" "$state" "$task_id")"
    if [[ ! -f "$packet_path" ]]; then
      printf '%s\n' "$report_path"
    fi
  done < <(find "$report_dir" -maxdepth 1 -type f -name 'TASK_*_human_report.md' -print0 | sort -z)
}

harness_sort_active_packets() {
  local active_dir="$1"
  find "$active_dir" -maxdepth 1 -type f -name 'TASK_*.md' -print0 | \
    while IFS= read -r -d '' file; do
      local priority task_id lane packet_type
      priority="$(harness_extract_field "$file" "Priority")"
      task_id="$(harness_task_id "$file")"
      lane="$(harness_extract_lane "$file")"
      packet_type="$(harness_extract_packet_type "$file")"
      printf '%s\t%s\t%s\t%s\t%s\n' \
        "$(harness_priority_rank "$priority")" \
        "$(harness_lane_rank "$lane")" \
        "$(harness_packet_type_rank "$packet_type")" \
        "${task_id:-$(basename "$file")}" \
        "$file"
    done | sort -t $'\t' -k1,1n -k2,2n -k3,3n -k4,4 | cut -f5-
}

harness_packet_is_done() {
  local file="$1"
  [[ "$(harness_extract_field "$file" "Status")" == "done" ]]
}

harness_active_done_predecessor_for_packet() {
  local active_dir="$1"
  local packet="$2"
  local lane task_id file other_lane other_task_id

  [[ -f "$packet" ]] || return 1

  lane="$(harness_extract_lane "$packet")"
  task_id="$(harness_task_id "$packet")"

  if ! harness_has_meaningful_value "$lane" || ! harness_has_meaningful_value "$task_id"; then
    return 1
  fi

  while IFS= read -r file; do
    [[ -n "$file" && "$file" != "$packet" && -f "$file" ]] || continue

    other_lane="$(harness_extract_lane "$file")"
    [[ "$other_lane" == "$lane" ]] || continue

    harness_packet_is_done "$file" || continue

    other_task_id="$(harness_task_id "$file")"
    [[ -n "$other_task_id" && "$other_task_id" < "$task_id" ]] || continue

    printf '%s\n' "$file"
    return 0
  done < <(harness_sort_active_packets "$active_dir")

  return 1
}

harness_organizer_state_file() {
  local repo_root="$1"
  local repo_hash
  repo_hash="$(printf '%s' "$repo_root" | sha1sum | awk '{print substr($1,1,12)}')"
  printf '%s/nacc-harness-organizer-%s.tsv\n' "${TMPDIR:-/tmp}" "$repo_hash"
}

harness_state_file_has_dispatch() {
  local state_file="$1"
  local packet="$2"
  local signature="$3"

  [[ -f "$state_file" ]] || return 1

  awk -F'\t' -v packet="$packet" -v sig="$signature" '
    $1 == packet && $3 == sig { found=1 }
    END { exit(found ? 0 : 1) }
  ' "$state_file"
}

harness_dispatch_state_for_packet() {
  local state_file="$1"
  local packet="$2"
  local role="$3"
  local signature="$4"

  # Keep a healthy same-role same-packet session latched while it is still working.
  # Mid-turn packet edits should not look like a fresh dispatch boundary.
  if harness_role_turn_is_actively_owned "$packet" "$role" && harness_tmux_role_session_matches_packet "$role" "$packet"; then
    if ! harness_tmux_role_session_matches_dispatch "$role" "$packet" "$signature"; then
      if harness_tmux_role_session_has_inflight_turn_for_packet "$role" "$packet"; then
        printf 'already-dispatched\n'
      else
        printf 'stale-session\n'
      fi
      return 0
    fi
    if harness_tmux_role_session_needs_redispatch_for_packet "$role" "$packet"; then
      printf 'stale-session\n'
    else
      printf 'already-dispatched\n'
    fi
    return 0
  fi

  if harness_tmux_cross_role_dispatch_awaits_ack "$packet" "$role" "$signature"; then
    printf 'waiting-source-ack\n'
    return 0
  fi

  if ! harness_state_file_has_dispatch "$state_file" "$packet" "$signature"; then
    printf 'new\n'
    return 0
  fi

  if harness_packet_waits_for_human_seed_after_dispatch "$packet" "$role"; then
    printf 'waiting-human\n'
    return 0
  fi

  if harness_tmux_role_session_needs_redispatch "$role" "$packet" "$signature"; then
    printf 'stale-session\n'
    return 0
  fi

  printf 'already-dispatched\n'
}

harness_role_turn_is_actively_owned() {
  local file="$1"
  local role="$2"
  local status owner

  status="$(harness_extract_field "$file" "Status")"
  owner="$(harness_extract_field "$file" "Owner Role")"

  if [[ "$status" == "in_progress" && "$owner" == "$role" ]]; then
    return 0
  fi

  if [[ "$role" == "planner" && "$status" == "draft" ]]; then
    return 0
  fi

  return 1
}

harness_tmux_available() {
  [[ -n "${TMUX:-}" ]] && tmux list-panes >/dev/null 2>&1
}

harness_tmux_sync_env_var() {
  local var_name="$1"
  local value="${!var_name-}"

  if [[ -n "$value" ]]; then
    tmux set-environment -g "$var_name" "$value" >/dev/null
  else
    tmux set-environment -gu "$var_name" >/dev/null 2>&1 || true
  fi
}

harness_tmux_sync_launch_environment() {
  local var_name

  for var_name in \
    HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \
    http_proxy https_proxy all_proxy no_proxy; do
    harness_tmux_sync_env_var "$var_name"
  done
}

harness_tmux_current_session() {
  if [[ -n "${TMUX_PANE:-}" ]]; then
    tmux display-message -p -t "$TMUX_PANE" '#S'
  else
    tmux display-message -p '#S'
  fi
}

harness_tmux_window_exists() {
  local window_name="$1"
  tmux list-windows -F '#{window_name}' | grep -Fxq "$window_name"
}

harness_tmux_role_window_name() {
  case "$1" in
    planner|coder|reviewer|organizer) printf 'agents\n' ;;
    test_runner|log_analyzer) printf 'tests\n' ;;
    qemu|vm|gdb|logger) printf 'debug\n' ;;
    *) return 1 ;;
  esac
}

harness_tmux_role_pane_title() {
  case "$1" in
    planner|coder|reviewer|organizer|test_runner|log_analyzer|qemu|vm|gdb|logger)
      printf 'nacc-%s\n' "$1"
      ;;
    *)
      return 1
      ;;
  esac
}

harness_tmux_role_pane_index() {
  case "$1" in
    planner|test_runner|qemu) printf '0\n' ;;
    reviewer|log_analyzer|gdb) printf '1\n' ;;
    coder|vm) printf '2\n' ;;
    organizer|logger) printf '3\n' ;;
    *)
      return 1
      ;;
  esac
}

harness_tmux_window_roles() {
  case "$1" in
    agents)
      printf 'planner\nreviewer\ncoder\norganizer\n'
      ;;
    tests)
      printf 'test_runner\nlog_analyzer\n'
      ;;
    debug)
      printf 'qemu\ngdb\nvm\nlogger\n'
      ;;
    *)
      return 1
      ;;
  esac
}

harness_tmux_set_pane_role() {
  local pane_id="$1"
  local role="$2"
  tmux set-option -p -t "$pane_id" @nacc_role "$role" >/dev/null
  tmux select-pane -t "$pane_id" -T "$(harness_tmux_role_pane_title "$role")"
}

harness_tmux_pane_get_option() {
  local pane_id="$1"
  local option_name="$2"

  tmux show-options -p -v -t "$pane_id" "$option_name" 2>/dev/null || true
}

harness_tmux_clear_dispatch_metadata() {
  local pane_id="$1"

  tmux set-option -p -t "$pane_id" @nacc_packet '' >/dev/null
  tmux set-option -p -t "$pane_id" @nacc_signature '' >/dev/null
  tmux set-option -p -t "$pane_id" @nacc_dispatch_ts '' >/dev/null
  tmux set-option -p -t "$pane_id" @nacc_handoff_ack '' >/dev/null
  tmux set-option -p -t "$pane_id" @nacc_ack_packet '' >/dev/null
  tmux set-option -p -t "$pane_id" @nacc_ack_source_role '' >/dev/null
  tmux set-option -p -t "$pane_id" @nacc_ack_next_role '' >/dev/null
  tmux set-option -p -t "$pane_id" @nacc_ack_signature '' >/dev/null
  tmux set-option -p -t "$pane_id" @nacc_ack_ts '' >/dev/null
}

harness_tmux_set_dispatch_metadata() {
  local pane_id="$1"
  local packet="$2"
  local role="$3"
  local signature="$4"

  tmux set-option -p -t "$pane_id" @nacc_role "$role" >/dev/null
  harness_tmux_clear_dispatch_metadata "$pane_id"
  tmux set-option -p -t "$pane_id" @nacc_packet "$packet" >/dev/null
  tmux set-option -p -t "$pane_id" @nacc_signature "$signature" >/dev/null
  tmux set-option -p -t "$pane_id" @nacc_dispatch_ts "$(date '+%Y-%m-%d %H:%M:%S %z')" >/dev/null
}

harness_tmux_retire_packet_panes() {
  local packet="$1"
  local repo_root="$2"
  local pane_line pane_id pane_role pane_packet current_command

  tmux list-panes -a >/dev/null 2>&1 || return 1

  while IFS='|' read -r pane_id pane_role pane_packet; do
    [[ -n "$pane_id" && "$pane_packet" == "$packet" ]] || continue

    current_command="$(harness_tmux_pane_current_command "$pane_id" || true)"
    harness_tmux_clear_dispatch_metadata "$pane_id"

    if [[ "$current_command" == "node" ]]; then
      tmux respawn-pane -k -t "$pane_id" "cd '$repo_root' && exec bash" >/dev/null
    fi

    printf '%s\t%s\n' "$pane_id" "${pane_role:-unknown}"
  done < <(tmux list-panes -a -F '#{pane_id}|#{@nacc_role}|#{@nacc_packet}')
}

harness_tmux_assign_window_roles() {
  local window_name="$1"
  local session_name pane_id pane_idx=0 role

  session_name="$(harness_tmux_current_session)"

  while IFS= read -r role; do
    [[ -n "$role" ]] || continue
    pane_id="$(tmux list-panes -t "${session_name}:${window_name}" -F '#{pane_index}|#{pane_id}' | \
      awk -F'|' -v pane_idx="$pane_idx" '$1 == pane_idx { print $2; exit }')"
    if [[ -n "$pane_id" ]]; then
      harness_tmux_set_pane_role "$pane_id" "$role"
    fi
    pane_idx=$((pane_idx + 1))
  done < <(harness_tmux_window_roles "$window_name")
}

harness_tmux_ensure_role_pane() {
  local role="$1"
  local workdir="${2:-$PWD}"
  local session_name window_name pane_index pane_count split_target pane_id

  window_name="$(harness_tmux_role_window_name "$role" || true)"
  pane_index="$(harness_tmux_role_pane_index "$role" || true)"
  session_name="$(harness_tmux_current_session)"

  if [[ -z "$window_name" || -z "$pane_index" ]]; then
    return 1
  fi

  if ! harness_tmux_window_exists "$window_name"; then
    return 1
  fi

  pane_count="$(tmux list-panes -t "${session_name}:${window_name}" | wc -l | tr -d ' ')"
  while (( pane_count <= pane_index )); do
    split_target="$(tmux list-panes -t "${session_name}:${window_name}" -F '#{pane_id}' | tail -n 1)"
    tmux split-window -d -v -t "$split_target" -c "$workdir" >/dev/null
    tmux select-layout -t "${session_name}:${window_name}" tiled >/dev/null
    pane_count="$(tmux list-panes -t "${session_name}:${window_name}" | wc -l | tr -d ' ')"
  done

  harness_tmux_assign_window_roles "$window_name"
  harness_tmux_find_pane_by_role "$role"
}

harness_tmux_find_pane_by_title() {
  local pane_title="$1"
  local session_name
  session_name="$(harness_tmux_current_session)"

  tmux list-panes -a -F '#{session_name}|#{pane_id}|#{pane_title}' | \
    awk -F'|' -v session="$session_name" -v title="$pane_title" '
      $1 == session && $3 == title {
        print $2
        exit
      }
    '
}

harness_tmux_find_pane_by_role() {
  local role="$1"
  local session_name window_name pane_index pane_title pane_id

  session_name="$(harness_tmux_current_session)"
  window_name="$(harness_tmux_role_window_name "$role" || true)"
  pane_index="$(harness_tmux_role_pane_index "$role" || true)"
  pane_title="$(harness_tmux_role_pane_title "$role" || true)"

  pane_id="$(tmux list-panes -a -F '#{session_name}|#{pane_id}|#{@nacc_role}' | \
    awk -F'|' -v session="$session_name" -v role="$role" '
      $1 == session && $3 == role {
        print $2
        exit
      }
    ')"
  if [[ -n "$pane_id" ]]; then
    printf '%s\n' "$pane_id"
    return 0
  fi

  if [[ -n "$pane_title" ]]; then
    pane_id="$(harness_tmux_find_pane_by_title "$pane_title" || true)"
    if [[ -n "$pane_id" ]]; then
      printf '%s\n' "$pane_id"
      return 0
    fi
  fi

  if [[ -n "$window_name" && -n "$pane_index" ]] && harness_tmux_window_exists "$window_name"; then
    tmux list-panes -t "${session_name}:${window_name}" -F '#{pane_index}|#{pane_id}' | \
      awk -F'|' -v pane_idx="$pane_index" '
        $1 == pane_idx {
          print $2
          exit
        }
      '
  fi
}

harness_tmux_role_session_matches_dispatch() {
  local role="$1"
  local packet="$2"
  local signature="$3"
  local pane_id pane_packet pane_signature

  pane_id="$(harness_tmux_find_pane_by_role "$role" || true)"
  if [[ -z "$pane_id" ]]; then
    return 1
  fi

  pane_packet="$(harness_tmux_pane_get_option "$pane_id" @nacc_packet)"
  pane_signature="$(harness_tmux_pane_get_option "$pane_id" @nacc_signature)"

  [[ "$pane_packet" == "$packet" && "$pane_signature" == "$signature" ]]
}

harness_tmux_role_session_matches_packet() {
  local role="$1"
  local packet="$2"
  local pane_id pane_packet

  pane_id="$(harness_tmux_find_pane_by_role "$role" || true)"
  if [[ -z "$pane_id" ]]; then
    return 1
  fi

  pane_packet="$(harness_tmux_pane_get_option "$pane_id" @nacc_packet)"
  [[ "$pane_packet" == "$packet" ]]
}

harness_tmux_set_handoff_ack_metadata() {
  local pane_id="$1"
  local packet="$2"
  local source_role="$3"
  local next_role="$4"
  local signature="$5"

  tmux set-option -p -t "$pane_id" @nacc_handoff_ack 1 >/dev/null
  tmux set-option -p -t "$pane_id" @nacc_ack_packet "$packet" >/dev/null
  tmux set-option -p -t "$pane_id" @nacc_ack_source_role "$source_role" >/dev/null
  tmux set-option -p -t "$pane_id" @nacc_ack_next_role "$next_role" >/dev/null
  tmux set-option -p -t "$pane_id" @nacc_ack_signature "$signature" >/dev/null
  tmux set-option -p -t "$pane_id" @nacc_ack_ts "$(date '+%Y-%m-%d %H:%M:%S %z')" >/dev/null
}

harness_tmux_role_session_has_handoff_ack_for_dispatch() {
  local source_role="$1"
  local packet="$2"
  local next_role="$3"
  local signature="$4"
  local pane_id ack_flag ack_packet ack_source_role ack_next_role ack_signature

  pane_id="$(harness_tmux_find_pane_by_role "$source_role" || true)"
  if [[ -z "$pane_id" ]]; then
    return 1
  fi

  if ! harness_tmux_role_session_matches_packet "$source_role" "$packet"; then
    return 1
  fi

  ack_flag="$(harness_tmux_pane_get_option "$pane_id" @nacc_handoff_ack)"
  ack_packet="$(harness_tmux_pane_get_option "$pane_id" @nacc_ack_packet)"
  ack_source_role="$(harness_tmux_pane_get_option "$pane_id" @nacc_ack_source_role)"
  ack_next_role="$(harness_tmux_pane_get_option "$pane_id" @nacc_ack_next_role)"
  ack_signature="$(harness_tmux_pane_get_option "$pane_id" @nacc_ack_signature)"

  [[ "$ack_flag" == "1" ]] || return 1
  [[ "$ack_packet" == "$packet" ]] || return 1
  [[ "$ack_source_role" == "$source_role" ]] || return 1
  [[ "$ack_next_role" == "$next_role" ]] || return 1
  [[ "$ack_signature" == "$signature" ]]
}

harness_packet_latest_artifact_age_sec() {
  local packet="$1"
  local repo_root_hint report_path now_epoch newest_epoch age report_epoch

  [[ -f "$packet" ]] || return 1

  newest_epoch="$(stat -c '%Y' "$packet" 2>/dev/null || true)"
  [[ -n "$newest_epoch" ]] || return 1

  repo_root_hint="${repo_root:-$(cd "$(dirname "$packet")/../../../.." && pwd 2>/dev/null || true)}"
  report_path="$(harness_human_report_path "$packet" "$repo_root_hint" 2>/dev/null || true)"
  if [[ -n "$report_path" && -f "$report_path" ]]; then
    report_epoch="$(stat -c '%Y' "$report_path" 2>/dev/null || true)"
    if [[ -n "$report_epoch" && "$report_epoch" -gt "$newest_epoch" ]]; then
      newest_epoch="$report_epoch"
    fi
  fi

  now_epoch="$(date '+%s')"
  if (( now_epoch < newest_epoch )); then
    printf '0\n'
    return 0
  fi

  age="$((now_epoch - newest_epoch))"
  printf '%s\n' "$age"
}

harness_tmux_pane_current_command() {
  local pane_id="$1"
  tmux display-message -p -t "$pane_id" '#{pane_current_command}'
}

harness_tmux_pane_is_dead() {
  local pane_id="$1"
  [[ "$(tmux display-message -p -t "$pane_id" '#{pane_dead}')" == "1" ]]
}

harness_tmux_capture_recent() {
  local pane_id="$1"
  local lines="${2:-80}"
  tmux capture-pane -p -t "$pane_id" -S "-$lines"
}

harness_tmux_pane_has_inflight_turn() {
  local pane_id="$1"
  local recent

  recent="$(harness_tmux_capture_recent "$pane_id" 80 2>/dev/null || true)"
  recent="$(printf '%s\n' "$recent" | tail -n 30)"

  [[ -n "$recent" ]] || return 1

  if printf '%s\n' "$recent" | rg -q 'Working \([0-9]'; then
    return 0
  fi

  return 1
}

harness_tmux_pane_dispatch_age_sec() {
  local pane_id="$1"
  local dispatch_ts dispatch_epoch now_epoch

  dispatch_ts="$(harness_tmux_pane_get_option "$pane_id" @nacc_dispatch_ts)"
  [[ -n "$dispatch_ts" ]] || return 1

  dispatch_epoch="$(date -d "$dispatch_ts" '+%s' 2>/dev/null || true)"
  [[ -n "$dispatch_epoch" ]] || return 1

  now_epoch="$(date '+%s')"
  if (( now_epoch < dispatch_epoch )); then
    printf '0\n'
    return 0
  fi

  printf '%s\n' "$((now_epoch - dispatch_epoch))"
}

harness_tmux_pane_has_idle_codex_prompt() {
  local pane_id="$1"
  local recent
  local reconnect_line reconnect_retry reconnect_secs
  local dispatch_age_sec startup_window_sec

  startup_window_sec="${NACC_ORGANIZER_STARTUP_STALE_SEC:-180}"
  dispatch_age_sec="$(harness_tmux_pane_dispatch_age_sec "$pane_id" || true)"
  if [[ -z "$dispatch_age_sec" ]]; then
    dispatch_age_sec=0
  fi

  recent="$(harness_tmux_capture_recent "$pane_id" 60 2>/dev/null || true)"
  recent="$(printf '%s\n' "$recent" | tail -n 20)"

  if [[ -z "$recent" ]]; then
    return 1
  fi

  if printf '%s\n' "$recent" | rg -q 'stream disconnected before completion|Conversation interrupted - tell the model what to do differently'; then
    if printf '%s\n' "$recent" | rg -q 'Find and fix a bug in @filename|Improve documentation in @filename|Write tests for @filename|Summarize recent commits|Run /review on my current changes'; then
      return 0
    fi
  fi

  # Only let prompt-surface failures trigger auto-heal during the initial launch window.
  # Once a coder/reviewer/planner has been running for a while, a transient transport wobble
  # should not cause organizer to kill and replace the live pane out from under it.
  if printf '%s\n' "$recent" | rg -q 'MCP startup incomplete|Timeout waiting for child process to exit'; then
    if (( dispatch_age_sec <= startup_window_sec )); then
      return 0
    fi
    return 1
  fi

  # A transient backend reconnect should not immediately kill a live coding turn.
  # During startup we still self-heal if retries are exhausted or the reconnect lasts too long.
  reconnect_line="$(printf '%s\n' "$recent" | rg -o 'Reconnecting\.\.\. [0-9]+/5 \([0-9]+s' | tail -n 1 || true)"
  if [[ -n "$reconnect_line" ]]; then
    reconnect_retry="$(printf '%s\n' "$reconnect_line" | sed -E 's/.* ([0-9]+)\/5.*/\1/')"
    reconnect_secs="$(printf '%s\n' "$reconnect_line" | sed -E 's/.*\(([0-9]+)s/\1/')"
    if [[ -n "$reconnect_retry" && -n "$reconnect_secs" ]]; then
      if (( dispatch_age_sec <= startup_window_sec )) && (( reconnect_retry >= 5 || reconnect_secs >= 90 )); then
        return 0
      fi
    fi
  fi

  return 1
}

harness_tmux_pane_needs_redispatch() {
  local pane_id="$1"
  local current_command

  if harness_tmux_pane_is_dead "$pane_id"; then
    return 0
  fi

  current_command="$(harness_tmux_pane_current_command "$pane_id" || true)"
  if [[ "$current_command" != "node" ]]; then
    return 0
  fi

  if harness_tmux_pane_has_idle_codex_prompt "$pane_id"; then
    return 0
  fi

  return 1
}

harness_tmux_role_session_needs_redispatch_for_packet() {
  local role="$1"
  local packet="$2"
  local pane_id

  if ! harness_tmux_available; then
    return 1
  fi

  pane_id="$(harness_tmux_find_pane_by_role "$role" || true)"
  if [[ -z "$pane_id" ]]; then
    return 0
  fi

  if ! harness_tmux_role_session_matches_packet "$role" "$packet"; then
    return 0
  fi

  harness_tmux_pane_needs_redispatch "$pane_id"
}

harness_tmux_role_session_has_inflight_turn_for_packet() {
  local role="$1"
  local packet="$2"
  local pane_id

  if ! harness_tmux_available; then
    return 1
  fi

  pane_id="$(harness_tmux_find_pane_by_role "$role" || true)"
  if [[ -z "$pane_id" ]]; then
    return 1
  fi

  if ! harness_tmux_role_session_matches_packet "$role" "$packet"; then
    return 1
  fi

  harness_tmux_pane_has_inflight_turn "$pane_id"
}

harness_tmux_cross_role_dispatch_awaits_ack() {
  local packet="$1"
  local target_role="$2"
  local signature="$3"
  local source_role quiet_sec artifact_age pane_id

  if ! harness_tmux_available; then
    return 1
  fi

  source_role="$(harness_packet_source_role_for_dispatch "$packet" "$target_role" || true)"
  if [[ -z "$source_role" ]]; then
    return 1
  fi

  if ! harness_tmux_role_session_matches_packet "$source_role" "$packet"; then
    return 1
  fi

  if harness_tmux_role_session_has_handoff_ack_for_dispatch "$source_role" "$packet" "$target_role" "$signature"; then
    return 1
  fi

  pane_id="$(harness_tmux_find_pane_by_role "$source_role" || true)"
  quiet_sec="${NACC_ORGANIZER_IMPLICIT_ACK_QUIET_SEC:-20}"
  artifact_age="$(harness_packet_latest_artifact_age_sec "$packet" || true)"

  if [[ -n "$pane_id" ]] && [[ -n "$artifact_age" ]] && (( artifact_age >= quiet_sec )); then
    if harness_tmux_role_session_matches_packet "$source_role" "$packet" && \
       ! harness_tmux_pane_has_inflight_turn "$pane_id" && \
       ! harness_tmux_pane_needs_redispatch "$pane_id"; then
      return 1
    fi
  fi

  return 0
}

harness_tmux_role_session_needs_redispatch() {
  local role="$1"
  local packet="${2:-}"
  local signature="${3:-}"
  local pane_id

  if ! harness_tmux_available; then
    return 1
  fi

  pane_id="$(harness_tmux_find_pane_by_role "$role" || true)"
  if [[ -z "$pane_id" ]]; then
    return 0
  fi

  if [[ -n "$packet" && -n "$signature" ]] && ! harness_tmux_role_session_matches_dispatch "$role" "$packet" "$signature"; then
    return 0
  fi

  harness_tmux_pane_needs_redispatch "$pane_id"
}
