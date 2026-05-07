# Task Packet: NaCC T5.1a RISC-V Uaccess-Loop Mediation Feasibility Gate

## 0. Context

We are working on NaCC/RISC-V confidential-container PRIVATE_DATA protection.

Current security baseline:

    ordinary confidential-container user memory remains PRIVATE_DATA
    private bitmap remains enabled
    Linux/VMA/ELF/MEPC information must not be used as authority to unseal ordinary user pages

Previous T5.0 analysis found a clean active raw-uaccess subset:

    active raw-uaccess = 11,054 / 183,878 final PRIVATE_DATA traps = 6.0%
    to_user = 8,243 / 11,054 = 74.6%
    from_user = 2,811 / 11,054 = 25.4%

However, this active subset is not the true dominant hot region. It is only a clean wrapper-context subset.

The broader current-tree MEPC-family closeout reported:

    GENERIC_UACCESS = 115,332 / 182,586 = 63.2%

The revised interpretation is:

    Do not optimize syscall 63 or copy_page_to_iter specifically.
    Do not build a syscall-by-syscall router.
    Treat caller/syscall attribution as validation context only.
    The real candidate is the MEPC-family hotspot:
        fallback_scalar_usercopy
        __asm_copy_from_user
        __asm_copy_to_user

This task must determine whether the RISC-V uaccess loop can be used as a centralized mediation point.

Do not implement the portal yet.

---

## 1. Main Goal

Determine whether `fallback_scalar_usercopy` / `__asm_copy_*_user` can support a general, bounded, fail-closed mediation prototype.

The task must answer:

1. What is the exact RISC-V uaccess assembly/control-flow structure?
2. Do copy_from_user and copy_to_user share the same assembly body?
3. What registers carry src, dst, length, return value, and current copy state?
4. At PRIVATE_DATA trap time, can we recover:
       original src
       original dst
       remaining length
       current offset
       direction
       accessed address
       target PFN
       current protected task / cid
5. Can repeated per-byte/per-word PRIVATE_DATA traps in the scalar loop be converted into one bounded mediated range-copy?
6. What fraction of broad GENERIC_UACCESS traps are in a recoverable loop state?
7. If recoverability is low, why?
8. Should the next step be:
       implement bounded uaccess-loop mediation prototype,
       fix instrumentation,
       or abandon broad uaccess-loop portal and pick a smaller target?

This task is a feasibility gate, not an optimization task.

---

## 2. Non-Goals

Do not implement a mediation portal in this task.
Do not implement shared memory.
Do not implement syscall staging.
Do not unseal ordinary user pages.
Do not clear or relax private bitmap policy.
Do not change PRIVATE_DATA enforcement.
Do not modify application code.
Do not reintroduce manifest logic.
Do not optimize VDSO/VVAR.
Do not optimize rseq.
Do not optimize robust futex.
Do not optimize teardown.
Do not create syscall-specific patches.
Do not build a syscall router.

This task is analysis, instrumentation, and feasibility evaluation only.

---

## 3. Important Conceptual Rules

### 3.1 MEPC meaning

`mepc` is the kernel instruction address that accessed a protected page.

It is not the user PC.

A `mepc` inside `fallback_scalar_usercopy` means:

    Linux/RISC-V uaccess loop touched a PRIVATE_DATA-protected PFN

It does not by itself authorize changing protection.

---

### 3.2 MEPC is not policy authority

MEPC can identify the candidate mediation path.

But the authority for mediation must remain:

    protected task identity
    PFN ownership
    PRIVATE_DATA metadata
    validated user range
    copy direction
    bounded length

Do not use MEPC alone to relax or bypass PRIVATE_DATA.

---

### 3.3 Portal must not alias original user pages

Any future mediation must preserve:

    original user pages remain PRIVATE_DATA
    no ordinary user page is unsealed
    no original user page is mapped as shared portal memory

This task only checks whether a safe range-copy mediation is possible.

---

## 4. Required Static Analysis

Inspect the relevant RISC-V Linux source and assembly.

Locate and summarize:

    fallback_scalar_usercopy
    __asm_copy_from_user
    __asm_copy_to_user
    raw_copy_from_user
    raw_copy_to_user
    copy_from_user
    copy_to_user
    any RISC-V uaccess wrappers that lead to fallback_scalar_usercopy

For each relevant function, report:

    file path
    symbol address
    entry point
    argument registers
    return value convention
    how src/dst/len are represented
    whether from_user and to_user share the same body
    where load/store instructions occur
    where exception-table fixups happen
    how partial-copy failure is represented
    whether SUM or access permissions are toggled nearby

Required output:

    [NACC][uaccess-static]
    symbol=...
    file=...
    args=...
    direction=from_user/to_user/shared_body/unknown
    copy_state_registers=...
    return_semantics=...
    fixup_semantics=...
    notes=...

---

## 5. Required Runtime State Attribution

For every PRIVATE_DATA trap whose MEPC falls inside:

    fallback_scalar_usercopy
    __asm_copy_from_user
    __asm_copy_to_user
    raw usercopy loop body

record:

    workload id
    pid/tid/cid if available
    mepc
    mepc symbol
    instruction class:
        load
        store
        unknown
    access_va / stval if available
    resolved PFN if available
    PFN owner
    origin confidence if available
    current register snapshot needed to recover copy state:
        a0
        a1
        a2
        a3
        a4
        a5
        a6
        a7
        sp
        ra
        any loop registers used by the assembly
    caller/wrapper marker if available
    active_uaccess true/false
    direction if known:
        from_user
        to_user
        unknown
    syscall/path context if available
    copy state classification:
        recoverable
        partially_recoverable
        unrecoverable
    unrecoverable reason

Do not log excessive per-trap spam if too much output. Aggregate where possible, but keep enough top-row detail to debug.

---

## 6. Copy-State Recovery

Attempt to classify each uaccess-loop trap into one of:

    RECOVERABLE_TO_USER
    RECOVERABLE_FROM_USER
    RECOVERABLE_DIRECTION_UNKNOWN
    PARTIAL_STATE_MISSING_ORIGINAL_LENGTH
    PARTIAL_STATE_MISSING_BASE_POINTER
    PARTIAL_STATE_MISSING_DIRECTION
    UNRECOVERABLE_NO_WRAPPER_CONTEXT
    UNRECOVERABLE_REGISTER_STATE_INSUFFICIENT
    UNRECOVERABLE_EXCEPTION_FIXUP_CONTEXT
    UNRECOVERABLE_PFN_OWNER_MISSING
    UNRECOVERABLE_OTHER

For recoverable cases, compute if possible:

    original_src
    original_dst
    current_src
    current_dst
    original_len
    remaining_len
    copied_offset
    candidate_range_start
    candidate_range_len
    current_access_is_user_side=yes/no/unknown

Required output:

    [NACC][uaccess-state-summary]
    state=RECOVERABLE_TO_USER total=... share=...
    state=RECOVERABLE_FROM_USER total=... share=...
    state=PARTIAL_STATE_MISSING_DIRECTION total=...
    state=UNRECOVERABLE_NO_WRAPPER_CONTEXT total=...
    ...

---

## 7. Broad Generic-Uaccess Denominator Reconciliation

Reconcile the broad MEPC-family count and the active-uaccess subset.

For each workload, report:

    final_PRIVATE_DATA_total
    broad_GENERIC_UACCESS_total
    uaccess_loop_MEPC_total
    active_uaccess_total
    recoverable_loop_total
    unrecoverable_loop_total
    active_coverage_of_broad
    recoverable_coverage_of_broad
    recoverable_coverage_of_final

Required output:

    [NACC][uaccess-denominator-reconcile]
    workload=...
    final_private=...
    broad_generic=...
    loop_mepc=...
    active=...
    recoverable=...
    active_over_broad=...
    recoverable_over_broad=...
    recoverable_over_final=...

This is one of the most important outputs.

The task must explain why active_uaccess was only 6.0% of final traps.

---

## 8. Loop Hotspot Coverage

Group uaccess-loop traps by MEPC and recovery state.

Required output:

    [NACC][uaccess-loop-hotspot]
    pc=...
    symbol=...
    total=...
    recoverable=...
    unrecoverable=...
    direction=...
    top_state=...
    top_unrecoverable_reason=...
    share_of_broad_generic=...
    share_of_final_private=...

The report must answer:

    Is one scalar-loop PC responsible for most broad GENERIC_UACCESS?
    Are the largest loop PCs recoverable?
    Or are the largest loop PCs contextless/unrecoverable?

---

## 9. PFN Ownership Validation

For recoverable and partially recoverable cases, validate:

    accessed PFN owner
    whether PFN is PRIVATE_DATA
    whether PFN belongs to current protected task/cid if available
    whether origin metadata is exact/fallback/ambiguous/missing

Required output:

    [NACC][uaccess-pfn-owner]
    owner=PRIVATE_DATA total=...
    owner=UNKNOWN total=...
    origin_confidence=exact/fallback/ambiguous/missing total=...
    cid_match=yes/no/unknown total=...

If PFN ownership cannot be validated for top loop hotspots, mediation is not safe.

---

## 10. Feasibility Classification

For each workload and aggregate, classify feasibility:

    FEASIBLE_BOUNDED_TO_USER
    FEASIBLE_BOUNDED_FROM_USER
    FEASIBLE_BOUNDED_BOTH
    FEASIBLE_ONLY_ACTIVE_SUBSET
    NOT_FEASIBLE_DIRECTION_UNKNOWN
    NOT_FEASIBLE_STATE_UNRECOVERABLE
    NOT_FEASIBLE_PFN_OWNER_UNRELIABLE
    NOT_FEASIBLE_FRAGMENTED
    UNKNOWN_FEASIBILITY

Required output:

    [NACC][uaccess-feasibility]
    class=...
    total=...
    share_of_broad_generic=...
    share_of_final_private=...
    notes=...

---

## 11. Prototype Candidate Definition

If a prototype is feasible, recommend exactly one candidate.

Candidate choices:

    A. to_user-only bounded uaccess-loop mediation
    B. from_user-only bounded uaccess-loop mediation
    C. active-subset only mediation prototype
    D. selected workload/path validation prototype
    E. no prototype; fix instrumentation first
    F. no prototype; choose another optimization target

For the recommended candidate, provide:

    insertion point
    direction
    recognized instruction range
    required register state
    maximum copy length for prototype
    range validation rules
    PFN ownership checks
    fallback behavior
    expected coverage
    expected risk

Do not implement it.

---

## 12. Decision Rules

### Rule 1: Recoverable coverage

If recoverable_loop_total covers >= 50% of broad_GENERIC_UACCESS:

    proceed to prototype planning

If recoverable_loop_total covers 20-50%:

    prototype may be a mechanism demo, but expected payoff is limited

If recoverable_loop_total covers < 20%:

    do not implement broad uaccess-loop mediation yet

---

### Rule 2: Direction

If recoverable cases are mostly to_user:

    recommend to_user-only prototype

If mostly from_user:

    recommend from_user-only prototype

If direction remains unknown for most recoverable cases:

    do not implement; fix direction instrumentation

---

### Rule 3: Safety authority

If PFN ownership/cid validation is weak:

    do not implement mediation

If PFN ownership/cid validation is strong:

    mediation may be considered

---

### Rule 4: Active subset

If only active_uaccess subset is recoverable:

    downgrade prototype to mechanism demo
    do not claim large performance payoff

---

### Rule 5: Fragmentation

If different loop states require many special cases:

    do not implement broad portal
    recommend one exactly recognized loop case or stop at characterization

---

## 13. Workloads

Run the same eight workloads:

    1. printf alpha >/dev/null; echo kernel_read_done
    2. IFS= read -r line </etc/hostname; echo kernel_write_done
    3. anonymous/private fork repro; echo fork_private_done
    4. cat /etc/hostname; echo done
    5. echo alpha | cat; echo done
    6. wc -c /etc/hostname; echo done
    7. echo alpha | wc -c; echo done
    8. shared-memory repro; expected ping

All workloads must remain code-0.

Do not add new workloads in this task.

---

## 14. Final Report Required

Produce a report with:

    A. Branch/commit inspected
    B. Workload pass/fail table
    C. Static uaccess assembly summary
    D. Register/copy-state model
    E. Broad GENERIC_UACCESS vs active_uaccess reconciliation
    F. Recoverable loop-state summary
    G. Loop hotspot table
    H. Direction summary for broad loop cases
    I. PFN ownership / origin confidence summary
    J. Explanation of why active_uaccess was only 6.0%
    K. Feasibility classification
    L. Recommended next step:
         implement prototype
         repair instrumentation
         or choose another target
    M. If prototype is recommended, exact bounded prototype scope
    N. If not, exact reason why not

---

## 15. Acceptance Criteria

This task succeeds if:

    1. Workloads pass.
    2. Enforcement behavior is unchanged.
    3. No ordinary user page is unsealed.
    4. RISC-V uaccess assembly/register model is documented.
    5. The report reconciles broad GENERIC_UACCESS and active_uaccess.
    6. The report quantifies recoverable vs unrecoverable loop states.
    7. The report states whether a broad uaccess-loop mediation prototype is feasible.
    8. The report does not rely on syscall-specific routing as the main design.
    9. The report gives one concrete next step.

---

## 16. Explicit Warning

Do not optimize syscall 63.

Do not optimize copy_page_to_iter specifically.

Do not implement syscall-specific router logic.

The optimization boundary under investigation is:

    fallback_scalar_usercopy / __asm_copy_*_user MEPC-family

Caller/syscall data is validation context, not the optimization boundary.

The key feasibility question is:

    Can NaCC recover enough copy-loop state and PFN ownership information at this low-level uaccess loop to safely replace repeated PRIVATE_DATA traps with a bounded mediated range-copy?

If yes, proceed later with a very small prototype.

If no, do not force the portal design.