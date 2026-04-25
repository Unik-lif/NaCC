#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_file="$repo_root/docs/workflow/EXPERIMENT_LOG.md"
goal="${1:-}"

if [[ -z "$goal" ]]; then
  echo "usage: scripts/new_experiment.sh \"goal text\"" >&2
  exit 1
fi

timestamp="$(date '+%Y-%m-%d %H:%M:%S %z')"
tmp_file="$(mktemp)"

cat >"$tmp_file" <<EOF
# Experiment Log

新实验追加到顶部。每条都要能指回日志或产物路径。

---

## ${timestamp}

- Date/Time: ${timestamp}
- Goal: ${goal}
- Command Run:
- Expected Result:
- Actual Result:
- Artifact/Log Path:
- Conclusion:

$(tail -n +7 "$log_file")
EOF

mv "$tmp_file" "$log_file"
echo "appended experiment stub to $log_file"
