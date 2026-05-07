# Task Packet: NaCC T5.0 Generic Uaccess Caller-Chain Attribution and Portal Feasibility Gate

## 0. Context

We are working on NaCC/RISC-V confidential-container PRIVATE_DATA protection.

Current baseline policy:

    ordinary confidential-container user memory remains PRIVATE_DATA
    private bitmap remains enabled
    Linux/VMA/ELF/MEPC information must not be used as authority to unseal ordinary user pages

Previous manifest work showed that ELF-derived PT_LOAD information is not sufficient to drive fine-grained private/shared page policy. Do not reintroduce ELF-derived manifest logic in this task.

The latest current-tree PRIVATE_DATA hotspot closeout selected GENERIC_UACCESS as the first optimization candidate.

Important closeout results:

    total reduced final PRIVATE_DATA traps = 182,586

    GENERIC_UACCESS = 115,332 traps, 63.2%
    KERNEL_MEMCPY_ADJACENT = 36,228 traps, 19.8%
    RSEQ_ABI = 21,826 traps, 12.0%
    ROBUST_FUTEX_EXIT = 9,200 traps, 5.0%
    VDSO_TIME_UPDATE = 0
    USER_STRING_COPY = 0

The closeout recommended an explicit typed syscall/usercopy mediation or staging portal for generic user buffers as the first optimization target.

However, do NOT implement the portal yet.

Reason:
The closeout identifies fallback_scalar_usercopy / GENERIC_UACCESS as the dominant MEPC family, but it does not yet uniquely identify:

    which caller chains lead to fallback_scalar_usercopy
    whether the dominant direction is copy_from_user or copy_to_user
    which syscall/path contexts dominate
    whether KERNEL_MEMCPY_ADJACENT is truly downstream/adjacent to usercopy
    whether there is a single unified insertion point for a portal

Also, the origin attribution mechanism used by the closeout has evidence-quality caveats:

    bounded/lossy leaf-origin cache
    leaf-origin overwrites
    high pfn_fallback_ambiguous counters
    residual non-dominant invalid rows

Therefore, this task is a narrow attribution and feasibility-gate task.

It must answer:

    Is generic-uaccess concentrated enough to justify a unified typed mediation portal?

If yes, recommend the concrete portal insertion point and first prototype scope.

If no, recommend a narrower representative prototype or a different optimization path.

---

## 1. Task Goal

Perform a focused caller-chain attribution for GENERIC_UACCESS and KERNEL_MEMCPY_ADJACENT.

The goal is to decide whether we should implement a generic typed usercopy mediation portal, and where it should be inserted.

This task must answer:

1. Which caller chains lead to fallback_scalar_usercopy / __asm_copy_from_user / __asm_copy_to_user?
2. Is the dominant copy direction from_user, to_user, or unknown?
3. Which syscall/path contexts dominate generic uaccess?
4. Is KERNEL_MEMCPY_ADJACENT truly related to usercopy, or is it separate memory work?
5. Is there a unified insertion point that covers most traps?
6. If no unified insertion point exists, what is the smallest representative prototype target?
7. Is it safe and worthwhile to proceed to a typed mediation portal prototype?

This is not an optimization task.

---

## 2. Non-Goals

Do not implement optimization in this task.

Specifically:

    Do not implement typed mediation portal.
    Do not implement shared memory.
    Do not implement syscall staging buffer.
    Do not unseal ordinary user pages.
    Do not clear or relax private bitmap policy.
    Do not change PRIVATE_DATA enforcement.
    Do not modify application code.
    Do not reintroduce manifest logic.
    Do not implement VDSO/VVAR special classification.
    Do not implement rseq fast path.
    Do not implement robust futex fast path.
    Do not implement teardown batching.
    Do not attempt to patch many Linux hot paths.
    Do not broaden this task beyond GENERIC_UACCESS and KERNEL_MEMCPY_ADJACENT.

This task is attribution-only and decision-oriented.

---

## 3. Key Conceptual Rules

### 3.1 PRIVATE_DATA meaning

PRIVATE_DATA protects confidential-container user data pages or user-related protected ABI pages.

A PRIVATE_DATA trap means Linux/S-mode attempted to access a page/PFN protected by NaCC policy.

PRIVATE_DATA is about page/PFN ownership and protection class.

---

### 3.2 MEPC meaning

mepc is the kernel instruction address that performed the protected-data access.

It is not the user PC.

A kernel MEPC hotspot means:

    Linux kernel code was executing on behalf of a protected task
    and that instruction touched a PRIVATE_DATA-protected page

Do not interpret a kernel MEPC hotspot as kernel data ownership.

---

### 3.3 access_va vs origin_user_va

Do not classify only by access_va.

The correct attribution chain is:

    mepc
        -> kernel function family
            -> caller/call-site
                -> direction
                    -> syscall/path context
                        -> access_va
                            -> PA/PFN if available
                                -> PRIVATE_DATA owner/object kind if available
                                    -> origin_user_va or ABI object if available
                                        -> optimization candidate

If PFN origin metadata is unavailable or ambiguous, report it explicitly.

Do not hide ambiguity under generic UNKNOWN.

---

### 3.4 Generic uaccess risk

Do not assume:

    GENERIC_UACCESS is hot
    therefore a generic mediation portal is automatically correct

The key question is whether GENERIC_UACCESS is concentrated enough.

Good case:

    most traps go through one or two uaccess wrappers/call-sites
    direction is clear
    syscall/path contexts are manageable

Bad case:

    traps are spread across many unrelated callers
    direction is mostly unknown
    each path needs syscall-specific semantics
    a broad portal would become a Linux syscall-router engineering project

This task must distinguish these cases.

---

## 4. Scope

Focus only on PRIVATE_DATA traps whose MEPC family is:

    GENERIC_UACCESS
    KERNEL_MEMCPY_ADJACENT

Do not reclassify VDSO, rseq, robust futex, or teardown in this task except as background totals.

Known symbols/families from the previous closeout:

    fallback_scalar_usercopy
        -> GENERIC_UACCESS

    __asm_copy_from_user
    __asm_copy_to_user if present
    raw_copy_from_user / raw_copy_to_user wrappers if present
        -> GENERIC_UACCESS

    memset
    crc32_le_generic.part.0
    nearby bulk-memory helpers
        -> KERNEL_MEMCPY_ADJACENT

---

## 5. Required Instrumentation

For PRIVATE_DATA traps in GENERIC_UACCESS or KERNEL_MEMCPY_ADJACENT, record as many of the following as possible:

    workload id
    pid/tid/cid if available
    mepc
    mepc symbol
    caller PC / return address if available
    caller symbol if resolvable
    caller family if resolvable
    copy direction:
        from_user
        to_user
        unknown
    active syscall number/name if available
    semantic path if available:
        user_buffer_read
        user_buffer_write
        file_path
        mapping_update
        fork_exec
        exit_teardown
        unknown
    broad category:
        syscall_buffer_path
        teardown_mapping_update
    user_va if available
    length if available
    origin_va if available
    origin_vma_class if available
    origin_source if available
    origin confidence:
        exact
        pa_pfn_fallback
        ambiguous
        missing
    access_va if available
    pfn if available
    bytes if available

If direct caller PC is difficult to capture at trap time, instrument wrapper-level sites around:

    copy_from_user
    copy_to_user
    raw_copy_from_user
    raw_copy_to_user
    __copy_from_user
    __copy_to_user
    strncpy_from_user if present
    fallback_scalar_usercopy call entry if practical
    arch/riscv uaccess wrapper entry/exit if practical

The goal is not perfect stack traces.

The goal is to get enough caller/direction/path attribution to decide whether a unified portal insertion point exists.

---

## 6. Direction Classification

Classify each GENERIC_UACCESS trap into:

    from_user
        Linux/kernel reads from protected user memory

    to_user
        Linux/kernel writes to protected user memory

    unknown
        direction could not be determined

Use wrapper instrumentation if needed.

Examples:

    copy_from_user / raw_copy_from_user / __copy_from_user
        -> from_user

    copy_to_user / raw_copy_to_user / __copy_to_user
        -> to_user

    fallback_scalar_usercopy without caller context
        -> unknown unless caller/wrapper says otherwise

The final report must include the direction coverage.

If direction=unknown is too high, do not recommend portal implementation yet.

---

## 7. Caller-Chain Attribution

For each GENERIC_UACCESS row, identify the best available caller bucket.

Preferred order:

    1. direct wrapper function
    2. immediate return address symbol
    3. instrumented uaccess wrapper site
    4. syscall/path semantic context
    5. broad category only

Do not collapse everything into fallback_scalar_usercopy.

The report must answer:

    Are most fallback_scalar_usercopy traps reached through a small number of wrappers/call-sites?
    Or are they spread across many unrelated paths?

---

## 8. KERNEL_MEMCPY_ADJACENT Attribution

The closeout grouped KERNEL_MEMCPY_ADJACENT as supporting evidence for generic user-buffer mediation, but this is not guaranteed.

For each KERNEL_MEMCPY_ADJACENT hotspot, classify it as:

    likely_downstream_of_usercopy
    likely_independent_memory_work
    unknown_relation

Use caller symbol, workload, origin fields, and surrounding path context.

Known examples from closeout:

    memset
    crc32_le_generic.part.0

The report must answer:

    Should KERNEL_MEMCPY_ADJACENT be included in the expected payoff of the first portal prototype?
    Or should the first prototype target only GENERIC_UACCESS?

Default conservative rule:

    treat GENERIC_UACCESS 63.2% as direct target
    treat KERNEL_MEMCPY_ADJACENT 19.8% as possible secondary benefit only if caller relation supports it

---

## 9. Required Summary Logs

Add or produce the following summaries.

### 9.1 Uaccess Caller Summary

Format:

    [NACC][uaccess-caller-summary]
    callee=fallback_scalar_usercopy
    caller=<symbol or unknown>
    caller_pc=<pc or none>
    direction=from_user/to_user/unknown
    syscall=<nr/name or unknown>
    path=<semantic path>
    broad_category=<category>
    total_traps=...
    share_of_generic_uaccess=...
    unique_pfns=...
    bytes=... if available
    origin_confidence=exact/fallback/ambiguous/missing

### 9.2 Direction Summary

Format:

    [NACC][uaccess-direction-summary]
    direction=from_user total=... share=...
    direction=to_user total=... share=...
    direction=unknown total=... share=...

### 9.3 Syscall/Path Summary

Format:

    [NACC][uaccess-syscall-summary]
    syscall=<nr/name or unknown>
    path=<semantic path>
    total=...
    share=...
    direction=...
    top_caller=...

### 9.4 Workload Summary

Format:

    [NACC][uaccess-workload-summary]
    workload=<id>
    generic_uaccess_total=...
    top_caller=...
    top_direction=...
    top_path=...

### 9.5 Adjacent Memory Summary

Format:

    [NACC][uaccess-adjacent-summary]
    family=KERNEL_MEMCPY_ADJACENT
    symbol=memset/crc32/...
    caller=<symbol or unknown>
    relation=likely_downstream_of_usercopy/likely_independent_memory_work/unknown_relation
    total=...
    share=...
    origin_class=...
    notes=...

### 9.6 Insertion Candidate Summary

Format:

    [NACC][uaccess-insertion-candidate]
    candidate=<copy_from_user_wrapper / copy_to_user_wrapper / raw_uaccess_wrapper / arch_riscv_uaccess / NaCC_uaccess_mediation_layer / selected_syscall / unknown>
    estimated_coverage=...
    direction=from_user/to_user/both/unknown
    implementation_scope=small/medium/large/unknown
    safety_risk=low/medium/high/unknown
    recommendation=proceed/defer/repair_attribution
    notes=...

### 9.7 Origin Quality Summary

Format:

    [NACC][uaccess-origin-quality]
    exact=...
    pa_pfn_fallback=...
    ambiguous=...
    missing=...
    leaf_origin_overwrites=...
    pfn_fallback_ambiguous=...

This is important because previous evidence used a bounded/lossy leaf-origin cache.

---

## 10. Workloads

Run the same eight workloads used in the current closeout:

    1. printf alpha >/dev/null; echo kernel_read_done
    2. IFS= read -r line </etc/hostname; echo kernel_write_done
    3. anonymous/private fork repro; echo fork_private_done
    4. cat /etc/hostname; echo done
    5. echo alpha | cat; echo done
    6. wc -c /etc/hostname; echo done
    7. echo alpha | wc -c; echo done
    8. shared-memory repro; expected ping

All workloads must remain code-0.

Do not change enforcement behavior.

---

## 11. Final Report Required

Produce a concrete report with these sections:

    A. Branch/commit inspected
    B. Workload pass/fail table
    C. GENERIC_UACCESS total and share
    D. KERNEL_MEMCPY_ADJACENT total and share
    E. Top fallback_scalar_usercopy callers
    F. Direction summary: from_user / to_user / unknown
    G. Syscall/path summary
    H. Workload summary
    I. KERNEL_MEMCPY_ADJACENT relation analysis
    J. Origin quality summary
    K. Portal insertion candidate ranking
    L. Decision: proceed to portal prototype or not
    M. If proceeding, recommended first prototype scope
    N. If not proceeding, recommended narrow repair or smaller target

---

## 12. Decision Rules

Use the following rules in the final recommendation.

### Rule 1: Direction confidence

If direction=unknown is more than 30% of GENERIC_UACCESS:

    do not implement portal yet
    recommend direction attribution repair

If one direction is clearly dominant:

    from_user >= 60%
        recommend copy_from_user / user_to_kernel portal prototype first

    to_user >= 60%
        recommend copy_to_user / kernel_to_user portal prototype first

If both from_user and to_user are substantial:

    recommend one direction only for first prototype
    choose the larger one

---

### Rule 2: Caller concentration

If top 1-2 caller/wrapper buckets cover >= 70% of GENERIC_UACCESS:

    recommend unified portal insertion at that wrapper/layer

If top 3-5 caller/wrapper buckets cover >= 70%:

    recommend medium-scope portal only if they share the same uaccess abstraction

If caller coverage is highly fragmented:

    do not recommend broad portal
    recommend one selected syscall/path prototype or another smaller optimization target

---

### Rule 3: Syscall/path concentration

If one or two syscall/path buckets cover >= 60% of GENERIC_UACCESS:

    recommend selected syscall/path prototype

If many syscalls share the same wrapper and direction:

    recommend generic wrapper-level portal

If many syscalls require distinct semantics:

    do not implement broad portal in this iteration

---

### Rule 4: Adjacent memory routines

If KERNEL_MEMCPY_ADJACENT is likely downstream of usercopy:

    count it as possible secondary benefit
    but not as primary guaranteed payoff

If KERNEL_MEMCPY_ADJACENT is independent:

    exclude it from first portal payoff estimate

If relation is unknown:

    report it as unknown and target only GENERIC_UACCESS

---

### Rule 5: Origin quality

If exact/fallback origin quality is good enough for top caller rows:

    proceed with design recommendation

If most top rows are ambiguous or missing:

    recommend one small origin-tracking repair before optimization

---

## 13. Go / No-Go Criteria for Portal Prototype

### GO

Recommend proceeding to T5.1 portal prototype only if all are true:

    workloads pass
    enforcement unchanged
    no ordinary user page unsealed
    GENERIC_UACCESS remains dominant
    direction is mostly known
    top caller/wrapper coverage is concentrated
    a concrete insertion point is identified
    first prototype scope is bounded

### NO-GO

Do not recommend portal prototype if any are true:

    direction mostly unknown
    caller chains highly fragmented
    top rows mostly ambiguous/missing origin
    no clear insertion point
    portal would require many syscall-specific routers
    implementation would become broad Linux hot-path patching

If NO-GO, recommend exactly one alternative:

    direction attribution repair
    caller attribution repair
    selected syscall/path prototype
    rseq fast-path prototype
    robust futex null/empty fast path
    bounded teardown batching
    or stop at characterization

---

## 14. Explicit Warning

Do not turn this into broad Linux hot-path engineering.

The purpose is not:

    find every generic-uaccess path and patch it

The purpose is:

    determine whether generic-uaccess has enough concentration to justify one typed mediation portal prototype

NaCC should preserve the all-private baseline.

The portal, if later implemented, must not alias original user pages and must not unseal ordinary user pages.

The correct future optimization shape is:

    original user page remains PRIVATE_DATA
    typed portal is explicit, bounded, directional, and auditable
    trusted/mediated copy reduces repeated per-byte/per-word PRIVATE_DATA traps

This task only decides whether that future optimization is feasible.

Do not implement the portal in this task.