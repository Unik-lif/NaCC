# NaCC Session Bootstrap

Use this document to recover project context quickly in a fresh session without relying on long chat history.

Recommended read order:

1. If you want to know what is happening right now, open `docs/workflow/CURRENT_STATE.md`
2. If you want to know how this round should be coordinated, open `docs/workflow/README.md`
3. If you want stable design conclusions and code-entry references, read this file
4. If a session contains large raw logs, route them to log analyzer instead of mixing roles

Companion long-lived documents:

- `docs/agent/NACC_KNOWLEDGE_BASE.md`
- `docs/agent/BITTER_LESSONS.md`

## 1. Project Baseline

- repo root: `/home/link/NaCC`
- subrepos:
  - `linux/` (branch: `main`)
  - `opensbi/` (branch: `NoPIC`)

Key pushed commits referenced in the recent workflow:

- `linux`: `1f2f4c92d67f`
  - `[CODE]: linux attach forked child and unify exec state`
- `opensbi`: `8d77341`
  - `[CODE]: opensbi add child attach and exec path cleanup`
- `linux`: `45bba6df3a21`
  - `[CODE]: nacc fork consume ptp_list and register child pagetable metadata`
- `opensbi`: `38b0542`, `ba828aa`
  - `[CODE]: nacc fork emit packed child ptp_list for linux sync`
  - `[CODE]: ignore compile_commands artifacts in opensbi`
- top-level NaCC repo: `5583d37`, `376462e`
  - `[CODE]: add fork ptp_list notes and modules-update wrapper workflow`
  - `[CODE]: ignore compile_commands artifacts in root repo`

## 2. Stable Design Conclusions

- The current standard fork mainline is not legacy `nacc_fork` bypass. The real path is Linux-native `dup_mmap()/copy_page_range()`.
- Child secure page-table construction depends on NaCC hooks inside the standard fork path:
  - `__pte_alloc/__pmd_alloc` request secure PTP pages through SBI
  - `set_pte/set_ptes` write secure PTPs through SBI when needed
- `nacc_fork()` / `sm_nacc_fork()` remain only as legacy / compatibility paths and are no longer the semantic baseline.
- `NACC_FORKED` children currently use:
  - parent-side early `child pid -> cid` registration
  - lightweight first-user-return attach on the child side
  - convergence to `NACC_INITED + mm ACTIVE`
- `exec` currently uses the `NACC_EXEC` transition state:
  - the fresh exec `mm` is built first through ordinary Linux
  - successful exec converges through `nacc_exec()/sm_nacc_exec()` to perform `transfer_ptp + VM_NACC + attach`
  - same-pid exec and fork+exec now share this exec-attach chain
- Historical names such as `SBI_EXT_*REEXEC` and `AGENT_REEXEC_ENTRY_OFFSET` are intentionally kept as ABI / fixed-entry names.
- A newer accepted direction is now explicit:
  - `CSR_NACC_STATE` should be treated as a hart-local runtime mode
  - multi-process support likely requires an OpenSBI-owned per-thread secure runtime context rather than a single mode register acting as a full process state machine

## 3. Key Code Entrypoints

### Linux

- `linux/kernel/fork.c`
  - `dup_mmap()` stays on the standard `copy_page_range()` path
- `linux/arch/riscv/kernel/sys_riscv.c`
  - `nacc_attach_forked_child_if_needed()`
  - `nacc_exec()`
- `linux/arch/riscv/mm/nacc.c`
  - helper functions around NaCC `mm` state and page-table metadata
- `linux/include/asm-generic/pgalloc.h`
  - NaCC secure PTP allocation hooks
- `linux/arch/riscv/include/asm/pgtable.h`
  - secure `set_pte/set_ptes` write path
- `linux/arch/riscv/include/asm/nacc.h`
  - `NACC_FORKED` / `NACC_EXEC` / `NACC_INITED` definitions

### OpenSBI

- `opensbi/lib/sbi/sm/sm.c`
  - `sm_nacc_attach_forked_child()`
  - `sm_nacc_exec()`
  - thread-switch-side `CSR_NACC_STATE` updates
- `opensbi/lib/sbi/sbi_ecall_nacc.c`
  - SBI dispatch for child attach / exec attach
- `opensbi/include/sm/agent.h`
  - fixed agent exec-attach entry offset

### QEMU / Agent Runtime

- `qemu/target/riscv/op_helper.c`
  - `helper_acall`
  - `helper_aret`
  - current hart-local runtime fields such as `nacc_state`, `nacc_sstatus`, and `trampoline`
- `agent/src/entry.S`
  - `__reexec_entry`
  - `__trap_entry`
  - `__agent_exit`

## 4. Current Things To Re-Check In New Sessions

- Add a defensive null check in the NaCC branch of `__pte_offset_map_lock()` to avoid panic on unusual paths.
- Re-run `echo alpha | wc -c` on the latest fork/exec baseline; old filemap-root-cause claims cannot be reused blindly.
- Keep the old `SBI_EXT_*REEXEC` / `AGENT_REEXEC_ENTRY_OFFSET` names stable unless ABI pressure justifies a change.
- The project is still in prototype semantics. The near-term goal is to stabilize:
  - non-exec child
  - fork+exec
  - same-pid exec
- The newer high-value design question is trusted runtime-context ownership under multi-process execution.

## 5. Shortest Build / Debug Path

- OpenSBI only:
  - `PATH=/home/link/NaCC/riscv-tools/bin:$PATH make -C opensbi PLATFORM=generic CROSS_COMPILE=riscv64-unknown-linux-gnu- -j$(nproc)`
- Linux update through project Makefile:
  - `make linux-update`
- debug loop:
  - `make debug`
  - `make logger LOG=<tag>`
  - inspect `logs/*qemu*.log`

## 6. Modules Update / sudo

- original path:
  - `make modules-update`
- wrapper path:
  - `make modules-update-wrapper`
  - default wrapper: `sudo -n /usr/local/sbin/nacc-modules-update`
  - example script: `docs/agent/nacc-modules-update.example.sh`

## 7. Git Collaboration Habits

- top-level repo often uses:
  - `git add record Makefile docs/agent`
- subrepos often use:
  - `cd linux`
  - `git add *`
  - `git commit -m "[CODE]: ..."`
  - `git push`
- preferred message style:
  - `[CODE]: <module> <action> <purpose>`

## 8. Fresh-Session Checklist

1. Read this file plus `docs/agent/README.md`, `docs/agent/NACC_KNOWLEDGE_BASE.md`, and `docs/agent/BITTER_LESSONS.md`.
2. Run `git -C linux status -sb` and `git -C opensbi status -sb`.
3. Confirm whether the current task belongs mainly to Linux, OpenSBI, Agent, or the top-level repo.
4. Touch only necessary files and keep patches reviewable.
5. Do a minimal compile check before discussing commit / push.
