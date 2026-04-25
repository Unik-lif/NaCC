#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/harness_lib.sh"

packet="${1:-}"
role="${2:-}"

usage() {
  echo "usage: scripts/ack_role_turn.sh <task-packet-path> <role>" >&2
}

if [[ -z "$packet" || -z "$role" ]]; then
  usage
  exit 1
fi

if ! harness_is_supported_role "$role"; then
  echo "unsupported role: $role" >&2
  exit 1
fi

packet="$(harness_resolve_packet_path "$packet" "$repo_root" || true)"
if [[ -z "$packet" ]]; then
  echo "task packet not found" >&2
  exit 1
fi

pane_id=""
if [[ -n "${TMUX_PANE:-}" ]]; then
  pane_id="$TMUX_PANE"
fi
if [[ -z "$pane_id" ]]; then
  pane_id="$(
    tmux list-panes -a -F '#{pane_id}|#{@nacc_role}|#{@nacc_packet}' 2>/dev/null | \
      awk -F'|' -v role="$role" -v packet="$packet" '
        $2 == role && $3 == packet {
          print $1
          exit
        }
      '
  )"
fi
if [[ -z "$pane_id" ]]; then
  echo "could not find a live tmux pane for role $role and packet $packet" >&2
  exit 1
fi

pane_role="$(harness_tmux_pane_get_option "$pane_id" @nacc_role)"
if [[ -n "$pane_role" && "$pane_role" != "$role" ]]; then
  echo "pane role mismatch: pane=$pane_role expected=$role" >&2
  exit 1
fi

pane_packet="$(harness_tmux_pane_get_option "$pane_id" @nacc_packet)"
if [[ -n "$pane_packet" && "$pane_packet" != "$packet" ]]; then
  echo "pane packet mismatch: pane=$pane_packet expected=$packet" >&2
  exit 1
fi

infer_output="$(harness_infer_next_role "$packet")"
next_role="${infer_output%%$'\t'*}"
infer_output="${infer_output#*$'\t'}"
reason="${infer_output%%$'\t'*}"
action_state="${infer_output#*$'\t'}"

if [[ "$action_state" != "dispatch" || -z "$next_role" || "$next_role" == "human" ]]; then
  echo "no machine handoff to ack: ${reason:-no machine next owner}"
  exit 0
fi

source_role="$(harness_packet_source_role_for_dispatch "$packet" "$next_role" || true)"
if [[ -z "$source_role" ]]; then
  echo "no cross-role machine handoff to ack for $next_role"
  exit 0
fi

if [[ "$source_role" != "$role" ]]; then
  echo "packet currently expects the handoff ack from $source_role, not $role" >&2
  exit 1
fi

signature="$(harness_dispatch_signature "$packet" "$next_role")"
harness_tmux_set_handoff_ack_metadata "$pane_id" "$packet" "$role" "$next_role" "$signature"

printf 'acknowledged\t%s\t%s\t%s\t%s\n' "$packet" "$role" "$next_role" "$signature"
