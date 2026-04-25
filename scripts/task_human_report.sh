#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/scripts/harness_lib.sh"

ensure_mode=0
packet=""

usage() {
  echo "usage: scripts/task_human_report.sh [--ensure] <task-packet-path>" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ensure)
      ensure_mode=1
      shift
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

if [[ "$ensure_mode" -eq 1 ]]; then
  harness_ensure_human_report "$packet" "$repo_root"
else
  harness_human_report_path "$packet" "$repo_root"
fi
