# NaCC Agent Collaboration Notes

This document reorganizes reusable information from `AGENTS.md` and the older `.agent/` material into a practical collaboration guide for this repository.

When switching into a fresh session, start with:

- `docs/agent/SESSION_BOOTSTRAP.md`
- `docs/agent/NACC_KNOWLEDGE_BASE.md` for long-lived stable conclusions
- `docs/agent/BITTER_LESSONS.md` for costly historical mistakes to avoid repeating
- `docs/agent/REEXEC_DEBUG_20260312.md` for the March 12 same-pid reexec convergence results
- `docs/agent/FORK_DEBUG_20260315.md` for the March 15 fork+exec convergence results

## 1. Long-Lived Project Facts

- Core code directories:
  - `linux/`: NaCC kernel hooks plus mm / fork / exec / reclaim logic
  - `opensbi/`: M-mode monitor and SBI extension implementation
  - `agent/`: bare-metal agent
- Build-output directories:
  - `riscv-linux/`, `riscv-qemu/`, `riscv-linux-modules/`
  - avoid editing them directly
- Human collaboration used to be primarily Chinese; the current documentation entry set is being moved to English to make cross-agent reuse easier

## 2. Efficient Workflow

### 2.1 Minimal Build Strategy After Code Changes

- OpenSBI only:
  - `make opensbi`
- Linux only:
  - `make linux-update`
- Agent only:
  - `make agent-update`

### 2.2 Debug Loop

1. Start `make debug` to open the QEMU / VM / GDB tmux layout.
2. Reproduce the issue.
3. Run `make logger LOG=<tag>` to capture logs.
4. Focus on `logs/*qemu*.log` for oopses, page faults, and fork / exec / reclaim traces.

### 2.3 NaCC-Specific Checkpoints

- verify `thread.nacc_flag` state flow when relevant:
  - `NACC_PREPARE -> NACC_INITED -> (fork child) NACC_FORKED -> NACC_RECLAIM`
- verify the fork path covers:
  - OpenSBI secure page-table copy or write assistance where expected
  - Linux page-table metadata synchronization where required
- verify exec / exit teardown uses the intended NaCC path instead of accidentally falling back to an ordinary free path

## 3. Passwordless / Non-Interactive sudo

`make modules-update` already supports overriding the sudo command:

- default:
  - `make modules-update`
- fail immediately if passwordless sudo is unavailable:
  - `make modules-update SUDO="sudo -n"`
- already inside a root shell:
  - `make modules-update SUDO=""`

Prefer giving the current user the smallest possible NOPASSWD permissions for the required commands instead of broad passwordless sudo.

### 3.1 Wrapper Script With Absolute Paths

The repo provides an example:

- `docs/agent/nacc-modules-update.example.sh`

Recommended installation flow:

1. `sudo install -m 750 -o root -g root docs/agent/nacc-modules-update.example.sh /usr/local/sbin/nacc-modules-update`
2. `sudo visudo -f /etc/sudoers.d/nacc-modules-update`
3. add a rule such as:
   - `link ALL=(root) NOPASSWD: /usr/local/sbin/nacc-modules-update`

### 3.2 Makefile Wrapper Entry

The original `modules-update` path remains unchanged. There is also:

- `make modules-update-wrapper`

Default variables:

- `ROOT_SUDO="sudo -n"`
- `NACC_MODULES_UPDATE_WRAPPER="/usr/local/sbin/nacc-modules-update"`

Override example:

- `make modules-update-wrapper ROOT_SUDO="sudo -n" NACC_MODULES_UPDATE_WRAPPER="/usr/local/sbin/nacc-modules-update"`

## 4. Ongoing Documentation Discipline

- Record each crash root cause and repair action in `record/*.md` to avoid re-analyzing the same regression repeatedly.
- If fork / exec paths change again, update this documentation layer before making the implementation diverge further.
- Stable conclusions belong in `docs/agent/NACC_KNOWLEDGE_BASE.md`.
- High-cost misreads, wrong-log incidents, or bad rollbacks belong in `docs/agent/BITTER_LESSONS.md`.

## 5. Git Collaboration Notes

### 5.1 Top-Level NaCC Repo

- Common operations:
  - `git add record Makefile docs/agent`
  - `git commit -m "<message>"`
- Preferred message shape:
  - `[CODE]: update workflow docs and build wrapper targets`

### 5.2 Subrepos (`linux/`, `opensbi/`, `agent/`, `qemu/`)

- Common habit:
  - `cd linux`
  - `git add *`
  - `git commit -m "[CODE]: xxxxx"`
  - `git push`

Recommended style:

- describe `module + action + purpose`
- examples:
  - `linux`: `[CODE]: nacc fork consume ptp_list and register pagetable metadata`
  - `opensbi`: `[CODE]: nacc fork emit packed child ptp_list for linux sync`
