# 2026-05-19 NaCC COW Private Copy Sniff Closeout

## Context

This note records the workload 3 SUM-off private-source COW diagnostic from
`TASK_20260519_143706_nacc_no_normal_sum_off_bit_closer_look`.

The immediate goal was not to repair COW, but to decide whether the failure
needed more Linux branch chasing or whether the OpenSBI strict-deny evidence was
already enough to identify the problematic copy primitive.

Primary artifacts:

- Task packet:
  `docs/workflow/tasks/completed/TASK_20260519_143706_nacc_no_normal_sum_off_bit_closer_look.md`
- QEMU capture:
  `logs/TASK_20260519_143706_cow_sniff_w3_v2_01_20260519_153056_qemu_tmux_capture_live.log`
- Previous failed repair packet:
  `docs/workflow/tasks/completed/TASK_20260518_231819_nacc_cow_sumoff_private_copy_repair.md`

## Result

The diagnostic confirmed that workload 3 reaches the ordinary Linux page-copy
primitive with a NaCC private source page. The core failure is simpler than the
surrounding COW branch structure:

```text
copy one page
  from = NaCC private source PFN
  to   = newly allocated destination page
  Linux direct-map reads from
  OpenSBI strict-deny traps the read
```

The important QEMU lines are:

```text
[NACC][cow-sniff] stage=do_wp_page reuse_check ...
page_pfn=11f08f folio_anon=1 anon_exclusive=0 can_reuse=0 branch=copy

[NACC][strict-sumoff-first-deny] ... pa=0x11f08f000 pfn=0x11f08f

epc : __memcpy+0x3c/0xf8
ra  : do_wp_page+0x4a8/0x18c6
a0  : ffffffd69f4cb000
a1  : ffffffd69f08f000
a2  : 0000000000001000
badaddr: ffffffd69f08f000
```

The Linux sniff line and the OpenSBI strict-deny line agree on the source PFN:

```text
Linux do_wp_page page_pfn = 0x11f08f
OpenSBI denied source pfn = 0x11f08f
```

`addr2line -i -f` on the matching `riscv-linux/vmlinux` maps the fault path to:

```text
__memcpy
copy_user_highpage
copy_mc_user_highpage
__wp_page_copy_user
wp_page_copy
do_wp_page
```

This is enough to identify the problematic Linux action at the
`copy_mc_user_highpage(to, from, vaddr, vma)` level. The finer `do_wp_page()`
branch details explain why COW reached the copy path, but they are not required
for the next repair direction.

## Interpretation

The previous attempted COW repair chased `do_wp_page()` / `wp_page_copy()`
predicates too aggressively. It tried to classify a private-source COW instance
with Linux-side predicates such as `pte_nacc(vmf->orig_pte)`,
`nacc_private_leaf_page()`, and `nacc_src_page == vmf->page`, then divert only
that classified case to a trusted COW copy route.

That approach failed because the repair path did not trigger for the observed
workload 3 instance, and the logs did not show which predicate missed. In
retrospect, the more stable boundary is not the high-level COW branch tree, but
the low-level page-copy operation:

```text
copy_mc_user_highpage(to, from, vaddr, vma)
```

For this bug class, the relevant security question is direct:

```text
Is `from` a NaCC private data page?
```

If yes, Linux must not perform the ordinary direct-map copy. OpenSBI should
validate the source and perform the trusted copy, or fail closed. Linux can keep
the surrounding COW/rmap/PTE lifecycle unchanged.

## OpenSBI Evidence Sufficiency

With current OpenSBI strict-deny diagnostics plus symbol lookup, Linux-side
temporary sniffing is not required to identify the copy primitive:

- OpenSBI provides the denied private PFN, faulting VA, PA, PC, and RA.
- `addr2line -i -f` maps PC/RA back through the inlined Linux copy helper chain.
- The denied `pfn` is enough to prove the direct-map read targeted a private
  bitmap-managed page.

Linux sniffing is useful only when the next question is "which high-level COW
predicate made this happen?" For the lower-level repair direction, the
OpenSBI-first evidence is sufficient.

## Cleanup Decision

The temporary Linux `cow-sniff` patch in `linux/mm/memory.c` was diagnostic-only
and should not be committed. It was removed after the diagnostic result was
recorded.

The current OpenSBI gitlink update is still useful because it carries the
strict-deny/private-leaf resolution behavior that made this diagnosis reliable.

## Next Repair Direction

Prefer a small repair centered on the page-copy helper boundary:

```text
copy_mc_user_highpage(to, from, vaddr, vma)
```

Candidate behavior:

- Compute `from_pfn = page_to_pfn(from)` and `to_pfn = page_to_pfn(to)`.
- If the process/VMA/address is not a NaCC private candidate, use the original
  Linux copy path.
- If `from_pfn` is a NaCC private data page, call an OpenSBI trusted page-copy
  ecall instead of allowing Linux to read the direct-map source page.
- OpenSBI should validate the source PFN against its private bitmap and, where
  practical, bind it to the current root and `vaddr`.
- If OpenSBI rejects a private-source copy, do not fall back to ordinary Linux
  direct-map copy.

This keeps the repair focused on the actual faulting operation and avoids
spreading NaCC-specific COW branch predicates across unrelated Linux lifecycle
code.
