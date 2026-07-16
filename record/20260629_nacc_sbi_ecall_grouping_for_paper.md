# NaCC Linux/OpenSBI SBI Ecall Grouping for Paper

Date: 2026-06-29

This note records the current Linux/OpenSBI NaCC SBI ecall usage in a
paper-facing form. The goal is not to present an API manual, but to identify
where Linux crosses into OpenSBI for protected-state commit points.

All Linux-side calls below use `SBI_EXT_NACC = 0x4E414343`. Linux often names
the function IDs as `SBI_EXT_NACC_*`, while OpenSBI names the same numeric IDs
as `SBI_EXT_LINUX_*`. The numeric FID is the ABI.

Core framing:

> Linux reaches OpenSBI only at protected-state commit points. Each handler
> receives Linux-prepared candidate state, validates it against
> monitor-maintained registration records and page metadata, and then performs
> the trusted pagetable, bitmap/refcount, copy, or retirement operation.

Important boundary note: `acall`/`aret` is not part of the normal SBI commit
call list. It belongs to the trap-return boundary. Ordinary delegated traps go
through Linux/agent trap handling, while OpenSBI is entered by Linux only at
protected ownership, mapping, copy, and retirement commit points.

## Registration / Context Calls

- `REGISTER`, FID `0x0`
  - Linux call shape: `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_REGISTER, cid, pid, 0, 0, 0, 0)`
  - OpenSBI handler: `sm_nacc_register(cid, pid)`
  - Meaning: register a protected process/container binding. OpenSBI records
    the CID/PID relationship and creates or refreshes monitor-side thread
    context.

- `UNREGISTER`, FID `0x15`
  - Linux call shape: `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UNREGISTER, pid, 0, 0, 0, 0, 0)`
  - OpenSBI handler: `sm_nacc_unregister(pid)`
  - Meaning: remove monitor-side PID/CID and thread-context state during exit.

- `INVOKE`, FID `0x1`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_INVOKE, agent_virt_start, pid, user_pt_regs, do_irq, excp_vect_table, current_gp)`
  - OpenSBI handler: `sm_nacc_invoke(...)`
  - Meaning: enter the initial NaCC agent path, or reuse the ready agent for a
    lightweight attach. This establishes the monitor/runtime context that lets
    the protected task enter the NACRE execution window.

- `REEXEC`, FID `0x8`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_REEXEC, agent_virt_start, pid, user_pt_regs, 0, 0, 0)`
  - OpenSBI handler: `sm_nacc_exec(...)`
  - Meaning: reattach after `exec` with a fresh `mm`. OpenSBI validates the
    protected page-table state, maps the agent, and loads thread context in
    `NACC_STATE_AGENT`.

- `INVOKE_CHILD`, FID `0x6`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_INVOKE_CHILD, agent_virt_start, pid, cid, 0, 0, 0)`
  - OpenSBI handler: `sm_nacc_invoke_child(...)`
  - Meaning: fork+exec child attach path that validates secure non-root PTP
    state and prepares the child in Linux mode without jumping through the
    agent.

- `ATTACH_FORKED_CHILD`, FID `0xb`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_ATTACH_FORKED_CHILD, agent_virt_start, pid, cid, user_pt_regs, 0, 0)`
  - OpenSBI handler: `sm_nacc_attach_forked_child(...)`
  - Meaning: first-user-return attach for a freshly forked protected child.
    OpenSBI validates inherited protected page-table ownership, loads the child
    context in agent mode, and enters the lightweight agent stub before user
    mode resumes.

- `VERIFY`, FID `0x4`
  - Linux scheduler call shapes:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_LINUX_VERIFY, prev_pid, next_pid, 0, 0, 0, 0)`
  - OpenSBI handler: `sm_init_agent_verify(prev_pid, next_pid)`
  - Meaning: scheduler context-switch boundary. OpenSBI saves/restores
    monitor thread context, including `CSR_NACC_SSTATUS`, `CSR_TRAMPOLINE`,
    and `CSR_NACC_STATE`.

- `AGENT_READY`, FID `0x1003`
  - Agent call shape: `sbi_ecall(SBI_EXT_NACC, SBI_EXT_AGENT_READY, 0, 0, 0, 0, 0, 0)`
  - OpenSBI handler: `sm_nacc_agent_ready()`
  - Meaning: the agent tells OpenSBI that first full initialization completed;
    later invocations can use lightweight attach.

## Protected Pagetable Calls

- `REQ_PTP`, FID `0x5`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_LINUX_REQ_PTP, new_pfn_buffer_pa, 0, 0, 0, 0, 0)`
  - OpenSBI handler: `sm_alloc_ptp(new_pfn_buffer_pa)`
  - Meaning: Linux asks OpenSBI to allocate a protected non-root page-table
    page from secure memory.

- `SET_PTES`, FID `0x9`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_SET_PTES, ptep_pa, pteval, nr, start_va, root_pgd_pa, 0)`
  - OpenSBI handler: `sm_nacc_set_ptes(...)`
  - Meaning: Linux supplies candidate PTE values. OpenSBI validates that the
    destination span is inside secure PTP memory, or that the slot is a legal
    root-L0 slot, then commits the PTE values.

- `WRPROTECT_PTES`, FID `0xa`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_WRPROTECT_PTES, ptep_pa, nr, 0, 0, 0, 0)`
  - OpenSBI handler: `sm_nacc_wrprotect_ptes(...)`
  - Meaning: trusted write-protect update for protected PTE slots.

- `UPDATE_PTE`, FID `0x14`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UPDATE_PTE, op, ptep_pa, operand, start_va, root_pgd_pa, flags)`
  - OpenSBI handler: `sm_nacc_update_pte(...)`
  - Meaning: trusted atomic PTE exchange or accessed-bit clearing for secure
    PTP/root-L0 slots. Current operations include `XCHG_ONE` and
    `TEST_CLEAR_YOUNG_ONE`.

- `TAG_ROOT`, FID `0xd`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_TAG_ROOT, pgd_pa, cid, 0, 0, 0, 0)`
  - OpenSBI handler: `sm_nacc_tag_root(pgd_pa, cid)`
  - Meaning: mark the root page table as monitor-tracked `ROOT_L0`.

- `RETIRE_ROOT`, FID `0xc`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_RETIRE_ROOT, pgd_pa, 0, 0, 0, 0, 0)`
  - OpenSBI handler: `sm_nacc_retire_root(pgd_pa)`
  - Meaning: retire monitor metadata for the protected root page table.

- `AGENT_MMAP`, FID `0x1002`
  - Agent call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_AGENT_MMAP, va, size, pa, perm, 0, 0)`
  - OpenSBI handler: `sm_agent_mmap(...)`
  - Meaning: agent bootstrap mapping request during initialization.

## Private Data Page Lifecycle Calls

- `ACQUIRE_PRIVATE_PFN`, FID `0x17`
  - Linux wrapper shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_ACQUIRE_PRIVATE_PFN, pfn, 0, 0, 0, 0, 0)`
  - OpenSBI handler: `sm_nacc_acquire_private_pfn(pfn, refs_out)`
  - Meaning: increment trusted private-data refcount and tag the PFN as
    `PRIVATE_DATA`. In the main protected PTE install path this is often
    performed inside OpenSBI's `nacc_prepare_secure_pte_update()` rather than
    as a standalone Linux-visible lifecycle operation.

- `RETIRE_PRIVATE_PFN`, FID `0x16`
  - Linux wrapper shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_RETIRE_PRIVATE_PFN, pfn, 0, 0, 0, 0, 0)`
  - OpenSBI handler: `sm_nacc_retire_private_pfn(pfn, retired_out)`
  - Meaning: decrement trusted private refcount. When the last reference is
    retired, the PFN returns to `NORMAL`.

- `COPY_USER_HIGHPAGE`, FID `0x18`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_COPY_USER_HIGHPAGE, from_pfn, to_pfn, vaddr, root_pgd_pa, pid, 0)`
  - OpenSBI handler: `sm_nacc_copy_user_highpage(...)`
  - Meaning: confidential COW page copy. If copying from `PRIVATE_DATA` to a
    normal target, OpenSBI marks the target `PRIVATE_COPY_PENDING` and copies
    the page contents in M-mode.

- `UACCESS_SCOPE_BEGIN`, FID `0x19`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UACCESS_SCOPE_BEGIN, scope_class, direction, user_va, bytes, desc_va, pid)`
  - OpenSBI handler: `nacc_private_data_uaccess_scope_begin(...)`
  - Meaning: begin a monitor-tracked private user-access scope, mainly for
    protected string/user-buffer reads.

- `UACCESS_SCOPE_END`, FID `0x1b`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UACCESS_SCOPE_END, scope_class, direction, user_va, bytes, result, pid)`
  - OpenSBI handler: `nacc_private_data_uaccess_scope_end(...)`
  - Meaning: close the private uaccess scope and clear monitor-side scope
    bookkeeping.

- `UACCESS_PRIVATE_GET_USER_READ`, FID `0x1a`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UACCESS_PRIVATE_GET_USER_READ, user_va, bytes, 0, 0, 0, 0)`
  - OpenSBI handler: `nacc_private_data_uaccess_private_get_user_read(...)`
  - Meaning: trusted scalar read from a private user mapping.

- `UACCESS_PRIVATE_COPY_TO_USER`, FID `0x1c`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UACCESS_PRIVATE_COPY_TO_USER, user_va, kernel_va, bytes, caller_pc, pid, 0)`
  - OpenSBI handler: `nacc_private_data_uaccess_private_copy_to_user(...)`
  - Meaning: trusted copy from kernel memory into a private user page. If the
    destination is a private COW leaf, OpenSBI returns a locked/denied result
    so Linux can fault it writable and retry.

- `UACCESS_PRIVATE_PUT_USER_WRITE`, FID `0x1d`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UACCESS_PRIVATE_PUT_USER_WRITE, user_va, value_lo, value_hi, bytes, caller_pc, pid)`
  - OpenSBI handler: `nacc_private_data_uaccess_private_put_user_write(...)`
  - Meaning: trusted scalar write into a private user mapping.

- `UACCESS_PRIVATE_COPY_FROM_USER`, FID `0x1e`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UACCESS_PRIVATE_COPY_FROM_USER, user_va, kernel_va, bytes, caller_pc, pid, 0)`
  - OpenSBI handler: `nacc_private_data_uaccess_private_copy_from_user(...)`
  - Meaning: trusted copy from a private user page into kernel memory.

- `UACCESS_PRIVATE_CLEAR_USER`, FID `0x1f`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_UACCESS_PRIVATE_CLEAR_USER, user_va, bytes, caller_pc, pid, 0, 0)`
  - OpenSBI handler: `nacc_private_data_uaccess_private_clear_user(...)`
  - Meaning: trusted zeroing of a private user page range.

## Teardown / Batch Retirement Calls

- `RECLAIM_PTP`, FID `0x2`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_RECLAIM_PTP, pfns_pa, count, 0, 0, 0, 0)`
  - OpenSBI handler: `sm_reclaim_ptp(pfns, count)`
  - Meaning: batch retire protected non-root PTP pages. Linux queues secure
    PTP PFNs in a reclaim list and flushes them in batches; OpenSBI frees the
    corresponding secure memory pages.

- `RECLAIM_AGENT_REGION`, FID `0x3`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_RECLAIM_AGENT_REGION, vm_start, vm_end, pgd_pa, 0, 0, 0)`
  - OpenSBI handler: `sm_reclaim_agent_region(vm_start, vm_end, pgd_pa)`
  - Meaning: remove agent-region mappings during `munmap` or teardown of
    `VM_NACC` regions.

## Debug / Profiling Calls

These are useful for measurement/debugging but should not be emphasized in the
main paper description of the Linux/OpenSBI security boundary.

- `PROFILE_RESET`, FID `0x20`
  - Meaning: reset OpenSBI NaCC profile counters when `NACC_PROFILE` is built.

- `PROFILE_READ`, FID `0x21`
  - Meaning: read one OpenSBI NaCC profile counter when `NACC_PROFILE` is built.

- `DEBUG`, FID `0x999`
  - Linux call shape:
    `sbi_ecall(SBI_EXT_NACC, SBI_EXT_LINUX_DEBUG, pgd_pa, 0, 0, 0, 0, 0)`
  - OpenSBI handler: `sm_pgtbl_debug(pgd_pa)`
  - Meaning: debug-only page-table/private-data statistics dump.

## Source Anchors

- Linux FID enum: `linux/arch/riscv/include/asm/sbi.h`
- OpenSBI FID macros: `opensbi/include/sm/sm.h`
- OpenSBI NACC ecall dispatcher: `opensbi/lib/sbi/sbi_ecall_nacc.c`
- Linux registration/context wrappers: `linux/arch/riscv/kernel/sys_riscv.c`
- Linux scheduler verify call: `linux/kernel/sched/core.c`
- Linux protected PTE wrappers: `linux/arch/riscv/kernel/sys_riscv.c`
- Linux secure PTE hooks: `linux/arch/riscv/include/asm/pgtable.h`
- Linux secure PTP allocation/free hooks: `linux/include/asm-generic/pgalloc.h`
- Linux root tag/retire hooks: `linux/arch/riscv/include/asm/pgalloc.h`
- Linux batch PTP retirement: `linux/arch/riscv/mm/nacc.c`, `linux/mm/mmap.c`
- OpenSBI registration/context implementation: `opensbi/lib/sbi/sm/sm.c`,
  `opensbi/lib/sbi/sm/thread_ctx.c`
- OpenSBI protected PTE implementation: `opensbi/lib/sbi/sm/sm.c`,
  `opensbi/lib/sbi/sm/vm.c`
- OpenSBI private PFN metadata: `opensbi/lib/sbi/sm/bitmap.c`
- OpenSBI private uaccess implementation: `opensbi/lib/sbi/sbi_trap_ldst.c`
- Linux trap-return boundary: `linux/arch/riscv/kernel/traps.c`
- Agent trap/return boundary: `agent/src/entry.S`
