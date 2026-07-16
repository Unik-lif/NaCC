You are helping implement a focused NACRE security patch.

Patch name:
Patch 2 — Convert Linux NACC hints into monitor-side VA range contracts / slot policy.

Background:
The current NACRE prototype uses Linux-side hints / VMA-derived paths to decide when a user mapping should be handled as NACC/private. This is useful because it separates NACRE paths from ordinary Linux VM corner cases. However, this hint must not become security authority.

The security bug we want to avoid is:
Linux VMA -> Linux-created PTE / _PAGE_NACC bit -> OpenSBI bitmap update

That is wrong because Linux can indirectly influence the monitor’s bitmap decision through VMA/PTE construction. VMA flags, Linux PTE contents, _PAGE_NACC, and “special” PTE markers must be treated only as routing inputs or candidate requests, never as the final authority for PRIV bitmap/refcount state.

Core design:
Keep Linux hints, but change their semantics.

Linux hint:
- “This VA range / PTE update should go through the NACRE protected path.”
- The hint helps Linux route to the right SBI call and avoid mixing NACRE mappings with ordinary Linux VM corner cases.
- The hint is untrusted.

Monitor range contract:
- Once OpenSBI accepts a hint, it records a monitor-owned VA range contract for the registered root/cid.
- After that, this VA range is NACRE-managed.
- Valid ordinary leaf mappings in this range must be committed by OpenSBI as NACC/PRIV mappings.
- Non-present mappings in this range remain private-pending.
- Special/shared/file-backed/system mappings are denied unless an explicit monitor-approved exception exists.

Important distinction:
Do NOT maintain slot policy per PFN.
Slot policy is per root/mm + VA range.
PFN metadata remains per physical page.

Target model:
1. VA/range policy says what kind of mapping is allowed at a virtual address.
2. PFN metadata says what role/state the physical page currently has.
3. OpenSBI commits a PTE only if both checks pass.

Please implement this as a small, focused patch. Do not implement full owner metadata, same-CID shared memory, cross-container grant/revoke, or full syscall-buffer mediation in this patch.

Required implementation tasks:

1. Add monitor-side range records

Add a protected OpenSBI-side data structure similar to:

    enum nacc_range_class {
        NACC_RANGE_PRIVATE_PENDING,
        NACC_RANGE_AGENT,
        NACC_RANGE_DENY_SPECIAL,
        NACC_RANGE_SHARED_PENDING,   // future; reject for now unless already supported
        NACC_RANGE_PUBLIC_SYSTEM,    // future; reject for now unless exact exception support exists
    };

    struct nacc_range_record {
        uintptr_t start;
        uintptr_t end;
        enum nacc_range_class class;
        uint64_t cid;
        pfn_t root_pfn;
        uint64_t generation;
        uint64_t flags;
    };

The exact type names can follow the existing NACRE/NaCC code style.

These records must live in monitor/OpenSBI protected metadata, not in Linux memory.

2. Add or refactor an SBI interface for declaring NACC-managed ranges

Linux may call something like:

    SBI_NACC_DECLARE_RANGE(root, start, end, class, flags)

or reuse an existing hint interface if one exists.

OpenSBI must validate:
- caller is a registered NACRE task;
- cid matches the registered task;
- root page table belongs to the registered task;
- range is page-aligned;
- range is in the user low-half address space;
- range does not overlap the agent mapping unless class is AGENT;
- range does not overlap existing conflicting range records;
- class is supported by the current prototype;
- range count is bounded to avoid unbounded metadata growth.

If accepted, the Linux hint becomes a monitor-owned range contract.

If rejected, Linux must not be able to silently fall back to ordinary non-NACC mapping for that same protected range.

3. Implement slot_policy(root, va)

Add a helper like:

    enum nacc_slot_class nacc_slot_policy(root_pfn, va)

It should consult monitor-owned root metadata and range records.

Minimal behavior for this patch:
- high-half kernel VA: not NACRE private; reject protected commit or route as kernel/normal depending on existing code;
- agent VA range: NACC_SLOT_AGENT;
- accepted PRIVATE_PENDING range: NACC_SLOT_PRIVATE_PENDING;
- accepted DENY_SPECIAL range: NACC_SLOT_DENY;
- no matching accepted range: NACC_SLOT_DENY for protected commit;
- future shared/public classes should return DENY unless explicitly implemented.

Do not infer slot policy from Linux VMA flags.
Do not infer slot policy from Linux PTE bits.
Do not infer slot policy from pte_special alone.

4. Refactor protected PTE commit path

For every OpenSBI path that commits a protected PTE update:

- Resolve caller identity from monitor-registered task state.
- Resolve target PTE page metadata.
- Validate that the target PTE page belongs to the caller’s root/cid.
- Reconstruct or identify the target VA from target PTE page metadata + index.
- Call slot_policy(root, va).
- Dispatch based on slot class.

Pseudo-code shape:

    int nacc_commit_pte_update(task, pte_page, pte_index, candidate_pte)
    {
        task_meta = nacc_lookup_registered_task(task);
        if (!task_meta)
            return -EPERM;

        ptp_meta = nacc_lookup_ptp_meta(pte_page);
        if (!ptp_meta)
            return -EPERM;

        if (ptp_meta->root_pfn != task_meta->root_pfn)
            return -EPERM;

        if (ptp_meta->cid != task_meta->cid)
            return -EPERM;

        va = nacc_reconstruct_va(ptp_meta, pte_index);
        slot = nacc_slot_policy(task_meta->root_pfn, va);

        switch (slot) {
        case NACC_SLOT_PRIVATE_PENDING:
            return nacc_commit_private_candidate(task_meta, va, candidate_pte);

        case NACC_SLOT_AGENT:
            return nacc_commit_agent_mapping(task_meta, va, candidate_pte);

        case NACC_SLOT_DENY:
        default:
            return -EPERM;
        }
    }

5. Private-pending semantics

For a PRIVATE_PENDING range:

Case A: candidate PTE is non-present / invalid
- Do not mark any PFN bitmap because there is no PFN.
- Keep the VA range as PRIVATE_PENDING.
- Return success only if this is a legitimate non-present protected slot operation.
- Later, when Linux faults in a valid page, it must call OpenSBI again and OpenSBI must commit the PFN as PRIV.

Case B: candidate PTE is valid ordinary user leaf
- Require ordinary leaf shape.
- Require user mapping.
- Require not special.
- Require not agent/metadata/root/protected PTP PFN.
- Require PFN role is NORM, or already PRIV owned by the same root/cid if current code has owner metadata.
- OpenSBI writes the final protected/NACC PTE.
- OpenSBI updates PFN bitmap/refcount to PRIV.
- Linux-provided _PAGE_NACC is only a request bit; the final protected PTE must be written by OpenSBI.

Case C: candidate PTE is special
- Reject for now.
- Do not allow generic pte_special passthrough.
- Do not mark special PFNs as PRIV.
- Do not skip bitmap/refcount just because pte_special is set.

Case D: candidate PTE is shared/file-backed/system mapping
- Reject unless there is an explicit monitor-side object model already implemented.
- Do not silently treat VM_SHARED, VM_MAYSHARE, memfd, POSIX shm, SysV shm, tmpfs shared mapping, or general MAP_SHARED as private confidential mappings.

6. VDSO/VVAR handling for this patch

Short-term policy:
- Protected NACRE containers should not install Linux-provided VDSO/VVAR.
- If the current Linux code installs VDSO/VVAR for NACRE tasks, disable it for protected tasks.
- Fork child sweep should not encounter VDSO/VVAR in a protected container after this patch.
- If sweep still sees unknown special low-half mappings, fail closed with a clear error.

Do NOT implement:

    if (pte_special)
        allow;

If future support is needed, VDSO/VVAR must become exact monitor-approved PUBLIC_SYSTEM mappings with recorded VA range, PFN, permissions, and source. That is not part of this patch.

7. Initialization sweep semantics

Refactor initial ELF/post-exec sweep so that sweep does not create authority from Linux VMA/PTE state.

Correct sweep behavior:

    for each low-half user PTE slot:
        slot = nacc_slot_policy(root, va);

        if pte is invalid:
            if slot == PRIVATE_PENDING:
                continue;  // pending, no PFN yet
            else:
                continue or reject depending on class

        if slot == PRIVATE_PENDING:
            require ordinary valid user leaf;
            require !pte_special;
            commit PFN as PRIV through OpenSBI;
            install final NACC PTE;
            continue;

        if slot == AGENT:
            require exact monitor-installed agent mapping;
            continue;

        otherwise:
            reject / fail closed.

Incorrect sweep behavior:
- Do not use VMA flags to decide that a page is confidential.
- Do not use Linux PTE _PAGE_NACC as authority.
- Do not allow special mappings by default.
- Do not skip unknown mappings silently.

8. Fork/clone/exec behavior

Fork:
- Child root/mm must inherit or derive the parent’s monitor-side range contracts.
- Fork child sweep should validate child mappings against inherited range contracts.
- Valid inherited private leaves increment monitor private refcount.
- Invalid private-pending slots remain pending.
- Unknown special mappings fail closed.

Clone with shared mm:
- Shared address-space threads should share the same root/range contract.
- New task still needs a registered NACRE thread context before entering the confidential execution window.

Exec:
- Old range contracts must be retired or invalidated as part of exec teardown.
- New exec creates a new set of monitor-accepted range contracts.
- Do not carry stale private-pending ranges across exec unless explicitly intended and validated.

Munmap/exit:
- Retire protected PTEs and decrement PFN refcounts before removing range contracts.
- PRIV -> NORM must clear confidential contents before the PFN returns to ordinary Linux lifecycle.

9. Security invariants to preserve

Please add comments or assertions around these invariants:

I1. Linux hint selects the NACRE path but does not authorize PRIV bitmap state.
I2. Once accepted, a hint becomes a monitor-owned range contract.
I3. A private-pending invalid PTE has no PFN bitmap yet, but it must later enter OpenSBI before becoming a valid mapping.
I4. _PAGE_NACC in a Linux candidate PTE is a request bit, not final authority.
I5. pte_special is never a generic bypass.
I6. Unknown low-half special mappings fail closed.
I7. Sweep validates against monitor range contracts; sweep does not infer security policy from VMA/PTE state.
I8. PFN bitmap/refcount is updated only at OpenSBI protected commit points.

10. Tests to add

Add small deterministic tests before large workloads.

Required tests:

Test 1: PROT_NONE pending range
- Declare a NACRE private range.
- Set it initially non-present / PROT_NONE.
- Verify no PFN bitmap is set while non-present.
- Later fault in a valid page.
- Verify OpenSBI commits it as PRIV/NACC.

Test 2: _PAGE_NACC outside accepted range
- Malicious or test Linux path creates a candidate PTE with _PAGE_NACC outside any monitor-accepted range.
- Expected: OpenSBI rejects.

Test 3: special PTE bypass attempt
- Attempt to map a confidential/private PFN using a candidate PTE marked special.
- Expected: OpenSBI rejects.
- This specifically tests that pte_special is not a bypass.

Test 4: omitted hint / missing range contract
- Try to create a valid user mapping for protected execution without declaring the range.
- Expected: initialization coverage check or runtime PTE commit fails closed.

Test 5: fork child sweep
- Run a protected container program that forks.
- Child inherits private-pending range contracts.
- Valid inherited leaves are committed/refcounted.
- Invalid pending slots stay pending.
- No unknown VDSO/VVAR special page should appear if VDSO is disabled.

Test 6: VDSO/VVAR disabled
- Confirm protected task /proc/self/maps does not contain [vdso] or [vvar], or equivalent platform output.
- Confirm basic program still runs via syscall fallback.

Test 7: private lifecycle sanity
- mmap/munmap loop.
- Verify no leaked PRIV PFNs and no leaked range records.

Optional tests:
- mprotect(PROT_NONE -> PROT_READ/WRITE) on a declared private range.
- fork + COW write correctness.
- invalid PTE shape rejection.
- malicious attempt to downgrade a PRIVATE_PENDING range into normal Linux mapping.

11. Debugging and observability

Add debug counters/logs:
- range_declared
- range_rejected
- private_pending_invalid_seen
- private_leaf_committed
- special_mapping_rejected
- nacc_pte_outside_range_rejected
- sweep_committed
- sweep_pending
- sweep_rejected
- fork_range_inherited
- range_retired
- leaked_range_records_on_exit

Logs should include root, cid, va range, class, and reason code where possible.

12. Non-goals for this patch

Do NOT implement:
- Full domain ownership metadata for every PFN/PTP page unless already trivial.
- Full cross-container isolation.
- Same-CID shared memory.
- Cross-container sharing/grant/revoke.
- Full syscall-buffer mediation.
- VDSO trusted public mapping support.
- Agent multicore redesign.

Do NOT broaden support just to make tests pass.
If an unsupported Linux mapping appears, fail closed and report it clearly.

13. Expected output

Please provide:
A. A short design summary explaining how Linux hints become monitor range contracts.
B. A list of code paths changed.
C. The actual patch.
D. The tests added and how to run them.
E. Any remaining unsafe paths or TODOs.
F. A short explanation of how this patch prevents VMA -> PTE -> bitmap laundering.

The most important success criterion:
After this patch, Linux may still use VMA/hint information to route requests into NACRE, but OpenSBI must never update PRIV bitmap/refcount solely because Linux VMA/PTE state says so. The final authority must be monitor-side range contract + protected PTE page ownership + PFN role checks.