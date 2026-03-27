# Known Good

This file records commands and entry points that are either known to work or have been repeatedly useful as a starting point.

## Build And Debug

- Linux quick compile sanity check
  - do not default to `make linux-update`
  - reuse the `make linux` parameters from the project `Makefile`:
    - `ARCH=riscv`
    - `O=/home/link/NaCC/riscv-linux`
    - `CROSS_COMPILE=/home/link/NaCC/riscv-tools/bin/riscv64-unknown-linux-gnu-`
  - single-object compile template:
    - `make ARCH=riscv -C /home/link/NaCC/linux O=/home/link/NaCC/riscv-linux CROSS_COMPILE=/home/link/NaCC/riscv-tools/bin/riscv64-unknown-linux-gnu- <path/to/object>.o`
  - if the workdir config is missing, initialize `riscv-linux/.config` from `config/linux_config` first
- build only OpenSBI
  - `make opensbi`
- update only Linux
  - `make linux-update`
- update only Agent
  - `make agent-update`
- start the debug environment
  - `make debug`
- recommended single-run test entry
  - `make debug VM_AUTO_CMD='<test command>'`
- multi-run automation script
  - `config/debug-batch.sh --cmd '<cmd1>' --cmd '<cmd2>'`
- example batch command file
  - `config/debug-batch.example.txt`
- recommended detached batch launcher
  - `tmux new-session -d -s <launcher> "cd /home/link/NaCC && config/debug-batch.sh --session-name <batch-session> --cmd-file config/debug-batch.example.txt > logs/<batch-session>.launcher.log 2>&1"`
- default batch report
  - return `logs/<batch-session>.launcher.log` first
- follow batch progress only when explicitly asked
  - `tail -f logs/<batch-session>.launcher.log`
- take over a detached batch session
  - `tmux attach -t <batch-session>`
- capture logs
  - `make logger LOG=<tag>`
- default cleanup
  - close the current test-runner tmux window after `make logger` succeeds
- update modules
  - `make modules-update`
- non-interactive wrapper path for modules
  - `make modules-update-wrapper`

## Core Entrypoints

- debug bootstrap doc: `docs/agent/SESSION_BOOTSTRAP.md`
- current status entry: `docs/workflow/CURRENT_STATE.md`
- current validation plan: `docs/workflow/PLAN_20260322_container_validation.md`
- runtime-context plan: `docs/workflow/PLAN_20260327_secure_runtime_context.md`
- VM auto-command config: `config/vm_link.sh`
- tmux debug entry: `config/tmux-debug.sh`
- batch-test entry: `config/debug-batch.sh`
- module-update wrapper example: `docs/agent/nacc-modules-update.example.sh`

## Common Scenarios

Recommended usage:

- If the user gives a full test command, run:
  - `make debug VM_AUTO_CMD='<user command>'`
- This ensures `[NaCC] Auto-running: ...` in the `nacc-vm` pane records the real command for the current round, which helps later log analysis.

- If the user gives multiple commands and does not want the current tmux UI occupied, use:
  - `config/debug-batch.sh --session-name <batch-session> --cmd-file <file>`
- If the run should be fully detached, wrap it in a launcher session and redirect stdout/stderr to `logs/<batch-session>.launcher.log`.
- Do not follow the launcher log continuously by default.

- Minimum smoke:
  - `docker run --security-opt seccomp=unconfined --rm busybox echo test`
- same-pid re-exec:
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /tmp/test.txt"`
- fork smoke:
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"`

For broader command coverage, see `PLAN_20260322_container_validation.md`.

## Reported Working Scenarios

These are still partly based on human reports and should be treated as "reported useful signals", not fully certified pass cases.

- 2026-03-23 detached batch runner:
  - `config/debug-batch.sh` can run multiple commands in an independent tmux session
  - the default first report should be the `launcher.log` path
- 2026-03-22 simple fork smoke:
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"`

## Reference Checkpoints

Historical checkpoints from `docs/agent/SESSION_BOOTSTRAP.md`, kept only for rollback reference:

- main repo: `5583d37`
- main repo: `376462e`
- `linux/`: `45bba6df3a21`
- `opensbi/`: `38b0542`
- `opensbi/`: `ba828aa`
