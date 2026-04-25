#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/harness_lib.sh"

launch_mode=0
interval=5
once_mode=0
force_mode=0
redispatch_cooldown_sec="${NACC_ORGANIZER_REDISPATCH_COOLDOWN_SEC:-45}"
packet_args=()
active_dir="$repo_root/docs/workflow/tasks/active"
state_file="$(harness_organizer_state_file "$repo_root")"
declare -A claimed_roles=()

usage() {
  cat >&2 <<'EOF'
usage: scripts/organizer_loop.sh [--launch] [--once] [--force] [--interval <seconds>] [task-packet...]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --launch)
      launch_mode=1
      shift
      ;;
    --once)
      once_mode=1
      shift
      ;;
    --force)
      force_mode=1
      shift
      ;;
    --interval)
      interval="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      packet_args+=("$1")
      shift
      ;;
  esac
done

mkdir -p "$(dirname "$state_file")"
touch "$state_file"

resolve_packets() {
  if [[ "${#packet_args[@]}" -gt 0 ]]; then
    local packet
    for packet in "${packet_args[@]}"; do
      harness_resolve_packet_path "$packet" "$repo_root"
    done
  else
    harness_sort_active_packets "$active_dir"
  fi
}

latest_dispatch_age_sec() {
  local packet="$1"
  local signature="$2"
  local ts now_epoch dispatch_epoch

  ts="$(
    awk -F'\t' -v packet="$packet" -v sig="$signature" '
      $1 == packet && $3 == sig { ts=$5 }
      END { if (ts != "") print ts }
    ' "$state_file"
  )"

  [[ -n "$ts" ]] || return 1

  dispatch_epoch="$(date -d "$ts" '+%s' 2>/dev/null || true)"
  [[ -n "$dispatch_epoch" ]] || return 1

  now_epoch="$(date '+%s')"
  if (( now_epoch < dispatch_epoch )); then
    printf '0\n'
    return 0
  fi

  printf '%s\n' "$((now_epoch - dispatch_epoch))"
}

record_dispatch() {
  local packet="$1"
  local role="$2"
  local signature="$3"
  local launch_target="$4"
  printf '%s\t%s\t%s\t%s\t%s\n' "$packet" "$role" "$signature" "$launch_target" "$(date '+%Y-%m-%d %H:%M:%S %z')" >> "$state_file"
}

launch_role_session() {
  local packet="$1"
  local role="$2"
  local signature="$3"
  local target_line target_type target_id target_window target_label target_summary target_display

  if harness_tmux_available; then
    target_line="$("$repo_root/scripts/tmux_launch_role.sh" "$packet" "$role")"
    target_type="$(printf '%s\n' "$target_line" | awk -F'\t' 'NR==1 { print $1 }')"
    target_id="$(printf '%s\n' "$target_line" | awk -F'\t' 'NR==1 { print $2 }')"
    target_window="$(printf '%s\n' "$target_line" | awk -F'\t' 'NR==1 { print $3 }')"
    target_label="$(printf '%s\n' "$target_line" | awk -F'\t' 'NR==1 { print $4 }')"

    if [[ "$target_type" == "pane" ]]; then
      target_summary="${target_type}:${target_label:-$target_id}"
      target_display="${target_label:-$target_id}"
    else
      target_summary="${target_type}:${target_id}"
      target_display="$target_id"
    fi

    record_dispatch "$packet" "$role" "$signature" "$target_summary"
    printf 'launched\t%s\t%s\t%s\t%s\n' "$packet" "$role" "$target_type" "$target_display"
  else
    printf 'launch-skipped\t%s\t%s\t%s\n' "$packet" "$role" "tmux-required"
  fi
}

process_packet() {
  local packet="$1"
  local role reason action_state signature task_id current_dispatch_state dispatch_age remaining infer_output source_role
  local archive_blocker archive_output archive_task_id lane

  [[ -f "$packet" ]] || return 0

  infer_output="$(harness_infer_next_role "$packet")"
  role="${infer_output%%$'\t'*}"
  infer_output="${infer_output#*$'\t'}"
  reason="${infer_output%%$'\t'*}"
  action_state="${infer_output#*$'\t'}"

  if [[ "$action_state" != "dispatch" || -z "$role" ]]; then
    printf 'skip\t%s\t%s\t%s\n' "$packet" "${role:--}" "$reason"
    return 0
  fi

  archive_blocker="$(harness_active_done_predecessor_for_packet "$active_dir" "$packet" || true)"
  if [[ -n "$archive_blocker" ]]; then
    archive_task_id="$(harness_task_id "$archive_blocker")"
    lane="$(harness_extract_lane "$packet")"
    if [[ "$launch_mode" -eq 1 ]]; then
      if archive_output="$("$repo_root/scripts/archive_task_packet.sh" "$archive_blocker" 2>&1)"; then
        printf '%s\n' "$archive_output"
        printf 'archived-predecessor\t%s\t%s\tlane:%s\n' "$packet" "${archive_task_id:-$(basename "$archive_blocker")}" "${lane:--}"
      else
        printf 'deferred\t%s\t%s\tarchive-failed:%s\n' "$packet" "$role" "${archive_task_id:-$(basename "$archive_blocker")}"
        printf '%s\n' "$archive_output" >&2
      fi
    else
      printf 'deferred\t%s\t%s\tlane-awaiting-archive:%s\n' "$packet" "$role" "${archive_task_id:-$(basename "$archive_blocker")}"
    fi
    return 0
  fi

  task_id="$(harness_task_id "$packet")"
  if [[ -n "${claimed_roles[$role]:-}" && "${claimed_roles[$role]}" != "${task_id:-$(basename "$packet")}" ]]; then
    printf 'deferred\t%s\t%s\trole-busy:%s\n' "$packet" "$role" "${claimed_roles[$role]}"
    return 0
  fi
  claimed_roles[$role]="${task_id:-$(basename "$packet")}"

  signature="$(harness_dispatch_signature "$packet" "$role")"

  if [[ "$force_mode" -ne 1 ]]; then
    current_dispatch_state="$(harness_dispatch_state_for_packet "$state_file" "$packet" "$role" "$signature")"

    case "$current_dispatch_state" in
      waiting-human)
        printf 'waiting-human\t%s\t%s\tawaiting-human-seed\n' "$packet" "$role"
        return 0
        ;;
      waiting-source-ack)
        source_role="$(harness_packet_source_role_for_dispatch "$packet" "$role" || true)"
        printf 'deferred\t%s\t%s\tsource-role-awaiting-ack:%s\n' "$packet" "$role" "${source_role:-unknown}"
        return 0
        ;;
      already-dispatched)
        printf 'already-dispatched\t%s\t%s\t%s\n' "$packet" "$role" "$reason"
        return 0
        ;;
      stale-session)
        if [[ "$launch_mode" -eq 1 ]]; then
          dispatch_age="$(latest_dispatch_age_sec "$packet" "$signature" || true)"
          if [[ -n "$dispatch_age" ]] && (( dispatch_age < redispatch_cooldown_sec )); then
            remaining="$((redispatch_cooldown_sec - dispatch_age))"
            printf 'retry-deferred\t%s\t%s\tstale-session-cooldown:%ss\n' "$packet" "$role" "$remaining"
            return 0
          fi
        fi
        ;;
    esac
  fi

  if [[ "$launch_mode" -eq 1 ]]; then
    launch_role_session "$packet" "$role" "$signature"
  else
    printf 'dispatch\t%s\t%s\t%s\n' "$packet" "$role" "$reason"
  fi
}

run_once() {
  local packet any=0
  claimed_roles=()
  while IFS= read -r packet; do
    [[ -n "$packet" ]] || continue
    any=1
    process_packet "$packet"
  done < <(resolve_packets)

  if [[ "$any" -eq 0 ]]; then
    echo "no active task packets"
  fi
}

if [[ "$once_mode" -eq 1 ]]; then
  run_once
  exit 0
fi

echo "NaCC organizer loop started"
echo "state file: $state_file"
echo "launch mode: $launch_mode"
echo "interval: ${interval}s"

while true; do
  run_once
  sleep "$interval"
done
