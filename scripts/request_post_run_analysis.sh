#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/harness_lib.sh"

launch_mode=0
packet=""
log_path=""

usage() {
  echo "usage: scripts/request_post_run_analysis.sh [--launch] [--log <path>] <task-packet>" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --launch)
      launch_mode=1
      shift
      ;;
    --log)
      log_path="${2:-}"
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

harness_set_field "$packet" "Status" "needs_analysis"
harness_set_field "$packet" "Post-Run Analysis Required" "yes"
harness_set_field "$packet" "Owner Role" "log_analyzer"
harness_set_field "$packet" "Next owner" "log_analyzer"

if [[ -n "$log_path" ]]; then
  harness_set_field "$packet" "Primary log path" "$log_path"
fi

echo "Updated packet for post-run analysis:"
echo "- Packet: $packet"
echo "- Status: needs_analysis"
echo "- Owner Role: log_analyzer"
echo "- Next owner: log_analyzer"
if [[ -n "$log_path" ]]; then
  echo "- Primary log path: $log_path"
fi
echo

if [[ "$launch_mode" -eq 1 ]]; then
  "$repo_root/scripts/start_next_role.sh" --launch "$packet"
else
  echo "Next step:"
  echo "  scripts/start_next_role.sh --launch $packet"
fi
