You are helping implement a focused NACRE hardening patch.

Patch name:
Agent-mediated semantic metadata path for PROT_NONE and VDSO/special mappings.

Goal:
Use the trusted NACRE Agent as a semantic front-end for selected syscall/trap cases before Linux turns them into untrusted VMA/PTE state.

The Agent should NOT become the final security database. The final authoritative state must remain in monitor/OpenSBI protected metadata. The Agent only parses the trusted syscall/trap intent, builds semantic records, and asks OpenSBI to install or update monitor-owned metadata.

This patch is a minimal hardening patch. Do not implement a full VMA mirror, full range-contract database, full shared-memory object model, cross-container sharing, or complete syscall-buffer mediation.

Background:
The current bug class we want to avoid is:

    Linux VMA -> Linux-created PTE / _PAGE_NACC -> OpenSBI bitmap update

This is unsafe because Linux VMA flags, Linux PTE contents, _PAGE_NACC bits, and pte_special can be influenced by untrusted Linux. They may route a request into the NACRE path, but they must never authorize PRIV bitmap/refcount state.

Core principle:
- Linux VMA/PTE state is an untrusted resource-management result.
- Agent syscall/trap semantic records are trusted intent inputs.
- Monitor/OpenSBI metadata is the final authority.
- OpenSBI is the only component that commits protected PTE updates, PRIV bitmap changes, and private refcount transitions.

The patch should implement:

    syscall/trap enters Agent
        -> Agent classifies selected exceptional mapping semantics
        -> Agent sends semantic record / intent token to OpenSBI
        -> OpenSBI validates and stores monitor-owned metadata
        -> Linux continues native VM path
        -> final PTE/bitmap/refcount commit checks monitor metadata, not Linux VMA/PTE authority

Important distinction:
Do NOT try to make Linux's vm_area_struct trusted.
Do NOT try to replicate all Linux VMAs.
The Agent should maintain or submit only a small trusted semantic map for NACRE exceptions:
- PROT_NONE empty ranges
- existing PRIV -> PROT_NONE transitions
- PROT_NONE -> accessible transitions
- VDSO/VVAR disabled policy
- trusted agent mapping range
- unknown special mapping denial
- optional future trusted system mapping, but do not implement it unless trivial

Recommended metadata model:

    enum nacc_sem_class {
        NACC_SEM_PROTNONE_EMPTY,
        NACC_SEM_PROTNONE_PRIV,
        NACC_SEM_VDSO_DISABLED,
        NACC_SEM_AGENT_RANGE,
        NACC_SEM_DENY_SPECIAL,
        NACC_SEM_TRUSTED_SYS_MAPPING,   // future only
    };

    struct nacc_sem_record {
        uint64_t cid;
        pfn_t root_pfn;
        uintptr_t start;
        uintptr_t end;
        enum nacc_sem_class class;
        uint64_t generation;
        uint64_t flags;

        // Used only when class == NACC_SEM_PROTNONE_PRIV
        pfn_t old_priv_pfn;
        uint64_t old_pte_perms;

        // Used only for future trusted system mapping
        pfn_t exact_pfn;
        uint64_t exact_perms;
    };

The exact field names can follow the current NACRE/NaCC style.

Data placement:
Preferred first version:
- Agent builds a semantic record in trusted Agent memory.
- Agent calls an SBI function to submit it.
- OpenSBI validates and copies the record into monitor-owned protected metadata.
- The Agent's copy is not authoritative.

Optional later version:
- Agent may allocate a metadata page from an Agent-reserved arena and hand it to OpenSBI.
- OpenSBI must validate, clear, adopt, and convert the page into monitor-owned metadata.
- After adoption, Agent must not directly mutate it except through SBI calls.

Do not leave authoritative metadata mutable only by Agent runtime state.

Required implementation tasks:

1. Add Agent-side semantic classification for selected syscalls/traps

The Agent already receives NACRE traps before delegating to Linux. Add classification for:

- mmap with PROT_NONE
- mprotect to PROT_NONE
- mprotect from PROT_NONE to readable/writable/executable
- munmap
- fork child attach / inherited PROT_NONE private mappings if this path exists
- exec first-entry metadata reset
- VDSO/VVAR policy during first Agent entry
- page fault path, only to correlate with existing semantic metadata

Do not attempt to implement full syscall-buffer mediation in this patch.

2. Add SBI interface for semantic records

Add or reuse SBI calls such as:

    SBI_NACC_DECLARE_SEMANTIC_RECORD(record)
    SBI_NACC_COMMIT_PROTNONE(root, va, len, flags)
    SBI_NACC_RETIRE_SEMANTIC_RANGE(root, va, len)
    SBI_NACC_QUERY_SEMANTIC_RECORD(root, va)

Exact names can follow existing code style.

OpenSBI must validate every record:
- caller is a registered NACRE task;
- cid/root match the monitor-registered task context;
- range is page-aligned;
- range is low-half user VA unless class is explicitly agent/system;
- range does not overlap the Agent mapping unless class is AGENT_RANGE;
- range does not conflict with existing monitor metadata;
- generation matches current root/cid generation;
- class is supported by current prototype;
- metadata count is bounded to avoid unbounded growth.

3. Default-private rule remains implicit

Do not record every Linux hint or every user VMA.

For a protected root:
- ordinary low-half valid user leaf mappings are default-private;
- OpenSBI commits them as PRIV only at protected commit points;
- invalid/non-present mappings do not need bitmap state unless they are hiding an existing PRIV PFN;
- Agent/monitor metadata is only needed for exceptions such as PROT_NONE-existing-private and VDSO/special policy.

4. PROT_NONE semantics

Handle two distinct cases.

Case A: mmap(PROT_NONE) or never-materialized PROT_NONE
- Agent records NACC_SEM_PROTNONE_EMPTY or PRIVATE_PENDING semantics if useful.
- No PFN exists.
- OpenSBI must not set PFN bitmap/refcount.
- Later, when the range becomes a valid ordinary mapping, OpenSBI must commit the PFN as PRIV before it can be used in the NACRE execution window.

Case B: existing PRIV page -> PROT_NONE
- This is security-sensitive.
- Agent sees mprotect(PROT_NONE) before delegating to Linux.
- Agent asks OpenSBI to preserve the old private PFN state.
- OpenSBI reads the old protected PTE, validates it is a NACRE private mapping, and records the old PFN in monitor metadata.
- OpenSBI keeps the PFN role as PRIV and preserves/increments/decrements refcount according to existing lifecycle rules.
- OpenSBI writes either:
    a) a monitor-defined NACC_PROTNONE PTE encoding that is non-present to hardware but preserves the PFN; or
    b) a protected protnone shadow record keyed by root+va -> old_priv_pfn.
- Linux must not be able to replace this with a generic non-present PTE that loses monitor ownership.

Case C: PROT_NONE -> accessible
- Agent sees mprotect(PROT_READ/WRITE/EXEC) or a relevant fault.
- Agent tells OpenSBI this is a restoration attempt.
- OpenSBI checks that the range has NACC_SEM_PROTNONE_PRIV metadata or a valid NACC_PROTNONE PTE.
- OpenSBI restores a valid NACC PTE only if the old PFN is still PRIV and belongs to the current root/cid.
- Linux-provided candidate PTE is only a request, not authority.

5. VDSO/VVAR and special PTE handling

Short-term policy for this patch:
- Protected NACRE tasks should not use Linux-provided VDSO/VVAR.
- During first Agent entry, Agent should record VDSO_DISABLED in monitor metadata.
- If the initial user stack contains AT_SYSINFO_EHDR / VDSO auxv entries and the implementation can safely patch them, remove or zero them so libc falls back to real syscalls.
- If the Linux arch path currently installs VDSO/VVAR for NACRE tasks before Agent can run, add a minimal Linux hook to skip VDSO/VVAR for protected tasks.
- Fork child sweep should not encounter VDSO/VVAR after this patch.

OpenSBI rule:
- Generic pte_special is never a bypass.
- Unknown special low-half mapping must fail closed.
- Do not write:
      if (pte_special) allow;
- Do not mark special PFNs as PRIV.
- Do not skip bitmap/refcount just because pte_special is set.

Future trusted system mapping support:
- A future trusted VDSO-like helper may be installed by Agent/monitor.
- It must be an exact allowlist:
      VA range matches recorded metadata;
      PFN matches recorded trusted helper PFN;
      permissions match expected RX/RO, not writable;
      PFN role is not PRIV;
      source is Agent/monitor-installed.
- Do not implement this in the current patch unless it is already straightforward.

6. Protected PTE commit path must consult monitor metadata

Refactor the protected PTE commit path so that it uses:

- registered task identity;
- cid/root binding;
- target protected PTE page metadata;
- default-private rule;
- monitor semantic records submitted by Agent;
- PFN bitmap/refcount state.

Do not trust:
- Linux VMA flags;
- Linux PTE _PAGE_NACC bit;
- Linux pte_special marker;
- Linux task_struct candidate mark;
- Linux-provided CID without monitor binding.

Pseudo-code shape:

    int nacc_commit_pte_update(task, pte_page, pte_index, candidate_pte)
    {
        task_meta = nacc_lookup_registered_task(task);
        if (!task_meta)
            return -EPERM;

        ptp_meta = nacc_lookup_ptp_meta(pte_page);
        if (!ptp_meta || ptp_meta->root_pfn != task_meta->root_pfn)
            return -EPERM;

        va = nacc_reconstruct_va(ptp_meta, pte_index);

        sem = nacc_lookup_sem_record(task_meta->root_pfn, va);

        if (candidate_pte is special) {
            if (sem is exact trusted system mapping)
                return commit_trusted_system_mapping(...); // future only
            return -EPERM;
        }

        if (candidate_pte is non-present) {
            if (old PTE is valid NACRE private)
                return commit_existing_priv_to_protnone(...);

            if (sem == PROTNONE_EMPTY or default-private pending)
                return keep_private_pending_no_pfn(...);

            return keep_private_pending_no_pfn_or_reject(...);
        }

        if (ordinary low-half user leaf) {
            return commit_default_private_leaf(...);
        }

        return -EPERM;
    }

7. Agent-to-monitor metadata handoff

Implement the first version as copy-in:
- Agent builds record.
- SBI copies and validates record into monitor metadata.
- Monitor metadata is authoritative.

Add debug counters:
- agent_sem_record_submitted
- agent_sem_record_accepted
- agent_sem_record_rejected
- protnone_empty_recorded
- protnone_priv_preserved
- protnone_restored
- vdso_disabled
- vdso_auxv_patched
- special_mapping_rejected
- nacc_candidate_outside_semantics_rejected
- sem_record_retired
- sem_record_leak_on_exit

8. Lifecycle handling

munmap:
- Agent records retirement intent if the range has semantic metadata.
- OpenSBI must retire protected PTEs and decrement PFN refcounts before deleting semantic records.
- PRIV -> NORM order must be:
    remove/rewrite protected mappings;
    decrement private refcount;
    clear confidential contents when refcount reaches zero;
    only then return PFN to NORM.

fork:
- Child must inherit relevant semantic records:
    PROTNONE_PRIV records;
    VDSO_DISABLED policy;
    AGENT_RANGE metadata.
- Inherited valid private mappings increment private refcount.
- Inherited PROTNONE_PRIV mappings preserve old PFN association.
- Unknown special mapping in child sweep fails closed.

exec:
- Retire old semantic records.
- Start a new generation for the new root/address space.
- Record VDSO_DISABLED for the new image.
- Do not carry stale protnone records across exec.

exit:
- All semantic records for the root/cid must be retired or reported as leaks.
- No live PROTNONE_PRIV record may remain without a corresponding protected PFN/refcount state.

9. Tests to add

Add small deterministic tests first.

Test 1: mmap(PROT_NONE)
- Protected app calls mmap(PROT_NONE).
- Verify no PFN bitmap is set for the empty range.
- mprotect to RW and touch the page.
- Verify OpenSBI commits the PFN as PRIV/NACC.

Test 2: existing private page -> PROT_NONE -> RW
- Allocate and write secret value.
- mprotect(PROT_NONE).
- Verify PFN remains PRIV and refcount is preserved.
- mprotect(RW), read value.
- Verify contents preserved and lifecycle cleanup succeeds.

Test 3: special PTE bypass attempt
- Attempt to map a confidential PFN using a candidate PTE marked special.
- Expected: OpenSBI rejects.
- This test proves pte_special is not a generic bypass.

Test 4: VDSO/VVAR disabled
- Run a protected task and inspect maps or equivalent platform state.
- Expected: no [vdso] / [vvar], or AT_SYSINFO_EHDR is removed/zeroed.
- Program should still run through syscall fallback.

Test 5: fork with PROT_NONE private page
- Parent creates private page, writes data, mprotect(PROT_NONE), then fork.
- Child inherits semantic metadata.
- No VDSO special failure.
- Refcounts and cleanup are correct.

Test 6: Linux PTE/VMA laundering attempt
- Simulate malicious Linux creating _PAGE_NACC or special candidate PTE without matching Agent/monitor semantic metadata.
- Expected: OpenSBI rejects.

Test 7: munmap/exit cleanup
- Repeat mmap/mprotect/munmap loop.
- Verify no leaked PRIV PFNs, protnone records, or semantic metadata records.

10. Non-goals

Do NOT implement:
- full VMA replication;
- full range contract for every hint;
- full domain ownership for all PFNs/PTPs unless already in progress;
- POSIX shm / SysV shm / memfd shared-object model;
- cross-container grant/revoke;
- full syscall-buffer mediation;
- trusted VDSO-like helper page unless minimal;
- Agent multicore redesign.

Do NOT broaden pte_special support just to make programs run.
Unsupported special mappings must fail closed with clear logs.

11. Expected output

Please provide:
A. Design summary of the Agent-mediated semantic metadata path.
B. Files and code paths changed.
C. The patch.
D. Tests added and how to run them.
E. Remaining unsafe paths / TODOs.
F. Explanation of how this prevents VMA -> PTE -> bitmap laundering.

Most important success criterion:
After this patch, Agent may classify syscall/trap semantics and help operate monitor metadata, but OpenSBI remains the final security authority. Linux VMA/PTE state can route requests, but cannot authorize PRIV bitmap/refcount state or bypass protection via PROT_NONE, _PAGE_NACC, or pte_special.