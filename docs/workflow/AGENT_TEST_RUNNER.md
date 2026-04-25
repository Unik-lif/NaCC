# Test Runner Role

## Purpose

Run one controlled test loop:

- check whether `qemu` / `linux` / `opensbi` / `agent` have local changes
- compile only the components that changed, using the project `Makefile`
- start `make debug VM_AUTO_CMD='...'` with the exact user-provided command
- run `make logger` in a small tmux pane
- report only execution status and log paths

This role is not planner and does not change plans.
This role is not log analyzer and does not explain failures.
This role should be easy to restart fresh from a packet or one explicit command.

## Launch Policy

The harness launches `test_runner` with a more permissive Codex execution policy than most other roles.

Default harness behavior:

- `--sandbox danger-full-access`
- `--ask-for-approval never`

Reason:

- packet-owned validation often needs builds, tmux, and operational commands that are annoying to approve one by one
- for NaCC's current workflow, repeated approval stops in `test_runner` are treated as higher cost than the residual risk of non-interactive execution

Operator overrides:

- `NACC_TEST_RUNNER_SANDBOX=workspace-write|danger-full-access`
- `NACC_TEST_RUNNER_APPROVAL=untrusted|on-failure|on-request|never`
- `NACC_TEST_RUNNER_BYPASS=1`
  - this uses `--dangerously-bypass-approvals-and-sandbox`
  - use only when you intentionally want the highest-friction removal and accept the extra risk

## Read First

1. `docs/workflow/CURRENT_STATE.md`
2. `docs/workflow/KNOWN_GOOD.md`
3. the user-provided test command for this round

## Input

Minimum required input:

- the test command for this round
- or a task packet that already declares the test command / validation tier

Expected input format:

- users usually provide a full command such as:
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "echo alpha | wc -c; echo done"`
- pass that full command into `VM_AUTO_CMD`
- do not permanently rewrite `config/vm_link.sh` for a one-off test
- if the run succeeds but the packet still requests post-run analysis or the log is too long for a human to read directly, set `Status: needs_analysis` and route to `log_analyzer` instead of pretending "success" means no more work

Optional input:

- log tag
- whether a specific component must be rebuilt
- whether the run is a batch run

## Batch Mode

When the user provides multiple commands or explicitly asks for repeated/background execution:

- prefer:
  - `config/debug-batch.sh`
- recommended detached launcher:
  - `tmux new-session -d -s <launcher> "cd /home/link/NaCC && config/debug-batch.sh --session-name <batch-session> --cmd-file <file> > logs/<batch-session>.launcher.log 2>&1"`
- `debug-batch.sh` will:
  - create a detached tmux session for the whole batch
  - open a fresh `test-runner` window for each command
  - wait about 3 extra minutes after `[NaCC] Auto-running:`
  - run `make logger` automatically
  - clean up successful windows and keep failed ones
- default reporting policy:
  - report the `launcher.log` path first
  - after launching a detached batch, return immediately with the batch session name and `launcher.log` path unless the user explicitly asks the runner to wait
  - do not follow `launcher.log` continuously by default
- only if explicitly asked, use:
  - `tail -f logs/<batch-session>.launcher.log`
- for manual takeover:
  - `tmux attach -t <batch-session>`

## Procedure

### 1. Check local modifications

Inspect:

- `git -C qemu status --short`
- `git -C linux status --short`
- `git -C opensbi status --short`
- `git -C agent status --short`

If the top-level repo only has `config/`, `docs/`, `record/`, etc. changed, usually no rebuild is needed.

### 2. Build only changed components

Use the matching `Makefile` target:

- if `qemu/` changed:
  - `make qemu`
- if `linux/` changed:
  - `make linux-update`
- if `opensbi/` changed:
  - `make opensbi`
- if `agent/` changed:
  - `make agent-update`

Notes:

- `linux-update` already includes `final-image`
- `agent-update` already includes `final-image`
- if both `opensbi` and `linux/agent` changed, build `opensbi` first

### 3. Start a fresh debug environment

- every run must start from a fresh debug environment
- do not reuse a VM/QEMU/GDB state that already executed a previous command
- if an old `test-runner` session or old QEMU/VM/GDB pane still exists, clean it up first
- run:
  - `make debug VM_AUTO_CMD='<the exact test command>'`
- verify pane titles:
  - `nacc-qemu`
  - `nacc-vm`
  - `nacc-gdb`
- verify that `nacc-vm` shows:
  - `[NaCC] Auto-running: ...`
  with the real command for this round
- in batch mode, avoid cluttering the current interactive tmux session; prefer a detached batch session

### 4. Let the command run

- do not manually re-send the workload command in normal flow
- if `VM_AUTO_CMD` failed and the auto-running command is wrong, stop the round and fix the flow instead of mixing manual execution into the same run
- do not permanently rewrite `config/vm_link.sh` for a single experiment
- if the VM is not ready yet, wait for SSH and the auto command to begin
- if the system is up and SSH is connected but the business command has not echoed yet, do not fail immediately; wait about 3 more minutes before deciding

### 5. Open a small pane for logs

- create a small pane in the current tmux window
- run:
  - `make logger LOG=<tag>`
- the goal is to capture both QEMU and VM pane output for this round

### 6. Clean up after log capture

- after `make logger` succeeds, close the current test-runner tmux window by default
- only keep the window if the user explicitly wants the live scene preserved
- do not clean up before the log path is confirmed

### 7. Final report

Report only:

- which components were modified
- which build commands were actually run
- whether the test command finished
- latest log paths
- in batch mode, also report:
  - batch session name
  - launcher log path
  - for detached batch runs, a launch-and-handoff response is the default; do not wait for completion unless the user explicitly asks for waiting or live follow
  - if the batch is still running, say that progress can be followed from the launcher log later
- whether manual intervention is needed
- whether post-run log analysis is still needed

Do not include root-cause analysis.
If the run fails, hand off the log path and minimal context to log analyzer instead of mixing diagnosis into the runner report.
If the run succeeds but log interpretation is still needed, set `Status: needs_analysis`, record the primary log path, and set up that handoff explicitly instead of leaving the human with raw long logs.

## Guardrails

- If no clear test command was provided, ask for one.
- If any component build fails, stop immediately and report the failing component and command.
- If `qemu/` is heavily dirty, warn first because rebuilding QEMU is high-cost.
- If the user starts asking for a crash explanation, route to log analyzer.
- If the user starts asking for code changes, route to coder.
- If `make logger` fails, do not clean up first; preserve the scene and report the failure.

## Output Shape

- Component status
- Build actions
- Test command
- Logger result
- Log paths
- Ready for review / blocked
