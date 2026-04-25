#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
packet="${1:-}"
role="${2:-}"

if [[ -z "$packet" || -z "$role" ]]; then
  echo "usage: scripts/run_role_session.sh <task-packet-path> <role>" >&2
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

prompt="$("$repo_root/scripts/launch_prompt.sh" "$packet" "$role")"

codex_args=(-C "$repo_root")

case "$role" in
  coder)
    # Coder needs a bit more operational headroom than the default interactive role because
    # the current NaCC workflow leans heavily on repo-local scripts, tmux inspection, and
    # bounded toolchain commands. This relaxes execution friction without changing the role's
    # semantic responsibility: heavy proof still belongs to reviewer/test_runner unless the
    # packet explicitly assigns it to coder.
    #
    # Operators can override these knobs per session:
    #   NACC_CODER_SANDBOX=workspace-write|danger-full-access
    #   NACC_CODER_APPROVAL=untrusted|on-failure|on-request|never
    #   NACC_CODER_BYPASS=1  -> use --dangerously-bypass-approvals-and-sandbox
    if [[ "${NACC_CODER_BYPASS:-0}" == "1" ]]; then
      codex_args+=(--dangerously-bypass-approvals-and-sandbox)
    else
      codex_args+=(--sandbox "${NACC_CODER_SANDBOX:-danger-full-access}")
      codex_args+=(--ask-for-approval "${NACC_CODER_APPROVAL:-on-failure}")
    fi
    ;;
  test_runner)
    # Test runner is intentionally lower-friction than the default interactive role.
    # The default is high-permission plus low-approval-interruption, because packet-owned
    # validation routinely needs builds, tmux, and other operational commands.
    # Operators can override these knobs per session if they want stricter or looser behavior:
    #   NACC_TEST_RUNNER_SANDBOX=workspace-write|danger-full-access
    #   NACC_TEST_RUNNER_APPROVAL=untrusted|on-failure|on-request|never
    #   NACC_TEST_RUNNER_BYPASS=1  -> use --dangerously-bypass-approvals-and-sandbox
    if [[ "${NACC_TEST_RUNNER_BYPASS:-0}" == "1" ]]; then
      codex_args+=(--dangerously-bypass-approvals-and-sandbox)
    else
      codex_args+=(--sandbox "${NACC_TEST_RUNNER_SANDBOX:-danger-full-access}")
      codex_args+=(--ask-for-approval "${NACC_TEST_RUNNER_APPROVAL:-never}")
    fi
    ;;
esac

exec codex "${codex_args[@]}" "$prompt"
