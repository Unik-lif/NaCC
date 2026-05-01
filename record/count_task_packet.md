# Task Packet: NaCC T4.3 Decision-Oriented PRIVATE_DATA Hotspot Closeout

## 0. Context

We are working on NaCC/RISC-V confidential-container PRIVATE_DATA protection.

Current baseline policy:

    ordinary confidential-container user memory remains PRIVATE_DATA
    private bitmap remains enabled
    no ordinary user page should be unsealed based on VMA, syscall, MEPC, or ELF information

Earlier manifest work showed that ELF-derived PT_LOAD information is not sufficient to drive private/shared page policy. Do not reintroduce ELF-derived manifest as a general policy driver.

Previous T4 baseline results showed two broad PRIVATE_DATA categories:

    syscall_buffer_path
    teardown_mapping_update

However, ASM/MEPC analysis showed that syscall_buffer_path is too coarse. It hides several different kernel code families:

    update_vsyscall / VDSO-VVAR time-data update
    rseq ABI maintenance
    exit_robust_list / robust futex exit walk
    strncpy_from_user / user string copy
    fallback_scalar_usercopy / __asm_copy_from_user / generic uaccess
    __memcpy adjacency near copy paths

The goal of this task is to convert the current broad attribution into a decision-ready table that tells us which optimization should be attempted first.

This task is not an optimization task.

---

## 1. Main Goal

Produce a closeout attribution report that answers:

    Which concrete MEPC family dominates PRIVATE_DATA traps?
    Which protected object kind dominates PRIVATE_DATA traps?
    Which optimization candidate has the highest expected payoff?
    Is the current data sufficient to start optimization, or do we still need one narrow instrumentation fix?

This task must avoid open-ended Linux hot-path hunting.

Do not try to enumerate every possible kernel path.
Only classify the known hot families and summarize the remaining UNKNOWN bucket.

---

## 2. Non-Goals

Do not implement optimization.

Specifically:

    Do not implement shared memory portal.
    Do not implement syscall staging buffer.
    Do not implement VVAR reclassification.
    Do not implement rseq fast path.
    Do not implement robust futex fast path.
    Do not implement teardown batching.
    Do not clear, relax, or bypass private bitmap policy.
    Do not use Linux VMA metadata as authority to unseal pages.
    Do not modify application code.
    Do not reintroduce ELF-derived manifest as page-policy driver.
    Do not broaden the task into patching many Linux hot paths.

This task is attribution closeout and optimization target selection only.

---

## 3. Important Conceptual Rules

### 3.1 MEPC meaning

mepc is the kernel instruction address that performed the protected-data access.

It is not the user PC.

A kernel MEPC hotspot means:

    Linux kernel code was executing on behalf of a protected task
    and that instruction touched a PRIVATE_DATA-protected page

It does not mean kernel business data is the protected object.

### 3.2 access_va vs origin/object

Do not classify only by access_va.

The correct chain is:

    mepc
        -> kernel function family
            -> access_va
                -> PA/PFN if available
                    -> PRIVATE_DATA owner/object kind if available
                        -> origin user VA/VMA or ABI object if available
                            -> optimization candidate

If PFN origin metadata is unavailable, still classify by MEPC family and object-kind heuristic, but report the missing origin data clearly.

### 3.3 Do not overgeneralize syscall_buffer_path

Do not conclude:

    syscall_buffer_path is hot
    therefore generic syscall staging buffer should be optimized first

Instead split syscall_buffer_path into:

    VDSO/VVAR time update
    rseq ABI
    robust futex exit
    user string copy
    generic uaccess
    memcpy adjacency
    other/unknown

Only the USER_STRING_COPY and GENERIC_UACCESS portions are direct candidates for syscall staging / mediation portal.

---

## 4. Required First Step: Parse Existing Evidence Before Editing Code

First, try to produce the closeout report using existing artifacts:

    QEMU logs
    final PRIVATE_DATA summaries
    MEPC hotspot summaries
    vmlinux.asm
    System.map or vmlinux symbols
    prior T4 baseline artifacts

Do not modify code unless existing artifacts are insufficient to answer the required questions.

If code changes are needed, keep them minimal and attribution-only.

---

## 5. MEPC Family Classification

Classify each top PRIVATE_DATA MEPC into one of:

    VDSO_TIME_UPDATE
    RSEQ_ABI
    ROBUST_FUTEX_EXIT
    USER_STRING_COPY
    GENERIC_UACCESS
    KERNEL_MEMCPY_ADJACENT
    MAPPING_TEARDOWN
    NACC_RUNTIME
    OTHER_KERNEL
    UNKNOWN_MEPC

Use vmlinux.asm, vmlinux symbols, System.map, addr2line, nm, or equivalent.

Known initial symbol mappings:

    update_vsyscall
        -> VDSO_TIME_UPDATE

    exit_robust_list
        -> ROBUST_FUTEX_EXIT

    clear_rseq_cs
    __rseq_handle_notify_resume
        -> RSEQ_ABI

    strncpy_from_user
        -> USER_STRING_COPY

    fallback_scalar_usercopy
    __asm_copy_from_user
    __asm_copy_to_user if present
        -> GENERIC_UACCESS

    __memcpy
        -> KERNEL_MEMCPY_ADJACENT

For every unresolved MEPC, report why it could not be resolved:

    missing symbol
    address outside vmlinux
    stripped/debug info unavailable
    parsing failure
    other

---

## 6. Object-Kind Classification

For each MEPC family, classify the likely protected object kind:

    VDSO_VVAR_TIME_DATA
    RSEQ_USER_ABI
    ROBUST_FUTEX_LIST
    USER_STRING
    GENERIC_USER_BUFFER
    MAPPING_METADATA
    ORDINARY_USER_DATA
    SHARED_EXPLICIT
    KERNEL_INTERNAL_OR_ALIAS
    UNKNOWN_OBJECT

Expected mapping:

    VDSO_TIME_UPDATE
        -> VDSO_VVAR_TIME_DATA

    RSEQ_ABI
        -> RSEQ_USER_ABI

    ROBUST_FUTEX_EXIT
        -> ROBUST_FUTEX_LIST

    USER_STRING_COPY
        -> USER_STRING

    GENERIC_UACCESS
        -> GENERIC_USER_BUFFER

    MAPPING_TEARDOWN
        -> MAPPING_METADATA or ORDINARY_USER_DATA depending on available origin data

If object kind is uncertain, say so explicitly.

---

## 7. Optimization Candidate Mapping

For each family, map to exactly one optimization candidate:

    VDSO_TIME_UPDATE
        -> VDSO/VVAR special classification or kernel-maintained ABI-data treatment

    RSEQ_ABI
        -> rseq disable experiment or rseq fixed-field fast path

    ROBUST_FUTEX_EXIT
        -> robust_list NULL/empty fast path

    USER_STRING_COPY
        -> bounded pathname/string mediation portal

    GENERIC_UACCESS
        -> explicit syscall staging / mediation portal

    MAPPING_TEARDOWN
        -> range batching / metadata cache / lazy teardown

    UNKNOWN_MEPC or UNKNOWN_OBJECT
        -> attribution repair before optimization

Do not implement any of these optimizations in this task.

---

## 8. Required Output Tables

Produce the following tables.

### 8.1 Workload Pass/Fail Table

For each workload:

    workload id
    command
    pass/fail
    exit code
    final PRIVATE_DATA total
    broad category split if available

### 8.2 MEPC Family Summary

Required columns:

    family
    total_traps
    share_of_total_private_data_traps
    load_count
    store_count
    unique_mepc_count
    top_mepc
    top_symbol
    top_workload

Example:

    family=VDSO_TIME_UPDATE
    total=...
    share=...
    load=...
    store=...
    top_symbol=update_vsyscall+0x...
    top_workload=...

### 8.3 Object-Kind Summary

Required columns:

    object_kind
    total_traps
    share
    main_mepc_family
    confidence_level
    notes

### 8.4 Family by Workload

Required columns:

    workload
    VDSO_TIME_UPDATE
    RSEQ_ABI
    ROBUST_FUTEX_EXIT
    USER_STRING_COPY
    GENERIC_UACCESS
    MAPPING_TEARDOWN
    UNKNOWN

This table should show whether a family is workload-specific or common across all workloads.

### 8.5 Family by Broad Category

Required columns:

    broad_category
    family
    total_traps
    share_within_broad_category

This is important because we need to know what syscall_buffer_path actually contains.

Example:

    broad_category=syscall_buffer_path
    family=VDSO_TIME_UPDATE
    total=...
    share_within_syscall_buffer_path=...

### 8.6 Candidate Optimization Ranking

Required columns:

    rank
    optimization_candidate
    supporting_family
    estimated_trap_share
    implementation_scope
    safety_risk
    expected_payoff
    recommendation

Candidate list:

    VDSO/VVAR special classification
    rseq disable or rseq ABI fast path
    robust futex NULL/empty fast path
    generic syscall staging / mediation portal
    pathname/string mediation portal
    mapping teardown batching
    attribution repair

Implementation scope should be one of:

    small
    medium
    large
    unknown

Safety risk should be one of:

    low
    medium
    high
    unknown

Expected payoff should be one of:

    low
    medium
    high
    unknown

### 8.7 Unknown Breakdown

UNKNOWN must not be a single bucket.

Break it into:

    MEPC_SYMBOL_MISSING
    MEPC_OUTSIDE_VMLINUX
    OBJECT_KIND_UNKNOWN
    BROAD_CATEGORY_ONLY
    PFN_ORIGIN_MISSING
    NO_SYSCALL_CONTEXT
    NO_MAPPING_CONTEXT
    PARSER_LIMITATION
    TRUE_UNKNOWN

Report counts for each.

---

## 9. Decision Rules

After producing the tables, choose exactly one first optimization target.

Use the following rules:

### Rule A: VDSO/VVAR

If VDSO_TIME_UPDATE is the largest concrete family or accounts for a large share of syscall_buffer_path:

    recommend VDSO/VVAR special classification as first optimization

But clearly state that this is not generic shared memory.
It is classification of kernel-maintained user ABI data.

### Rule B: Generic uaccess

If GENERIC_UACCESS or USER_STRING_COPY dominates after removing VDSO/rseq/robust-futex:

    recommend explicit typed mediation portal / syscall staging

But clearly state that original user pages remain private and the portal must not alias original user pages.

### Rule C: Robust futex

If ROBUST_FUTEX_EXIT is a major contributor, especially in fork/exec/exit-heavy workloads:

    recommend robust_list NULL/empty fast path

### Rule D: RSEQ

If RSEQ_ABI is a major contributor:

    recommend rseq disable experiment or fixed-field rseq ABI fast path

### Rule E: Mapping teardown

If MAPPING_TEARDOWN remains a major contributor after separating robust futex and rseq:

    recommend range batching / metadata cache / lazy teardown

### Rule F: Unknown too high

If UNKNOWN remains above 15% of total PRIVATE_DATA traps:

    do not recommend an optimization yet
    recommend one narrow attribution repair task

---

## 10. Required Final Answers

The report must explicitly answer:

    1. Is syscall_buffer_path still meaningful as an optimization target, or is it too broad?
    2. What concrete MEPC family is the largest contributor?
    3. Is update_vsyscall / VDSO-VVAR time update the largest concrete hotspot?
    4. How much trap volume is rseq ABI maintenance?
    5. How much trap volume is robust futex exit walk?
    6. How much trap volume is true generic uaccess?
    7. How much trap volume is user string/path copy?
    8. How much trap volume remains mapping/teardown after separating ABI paths?
    9. Is there enough evidence to start optimization?
    10. What is the single recommended first optimization target?

---

## 11. Acceptance Criteria

This task is successful only if:

    1. All workload results remain unchanged.
    2. No enforcement behavior is changed.
    3. No ordinary user page is unsealed.
    4. Top MEPCs are symbolized.
    5. Top MEPCs are grouped into families.
    6. syscall_buffer_path is broken down by concrete MEPC family.
    7. Object-kind summary is produced.
    8. Unknown breakdown is produced.
    9. Candidate optimization ranking is produced.
    10. Exactly one first optimization target is recommended.
    11. If evidence is insufficient, the report recommends exactly one narrow attribution repair task instead of optimization.

---

## 12. Explicit Warning

Do not turn this into broad Linux hot-path engineering.

The purpose is not:

    find every Linux path and patch it

The purpose is:

    use MEPC/object attribution to choose one representative optimization
    that preserves the all-private baseline
    and avoids unnecessary PRIVATE_DATA traps on a specific class of mediation path

Do not implement the optimization in this task.