# 2026-05-07 slab bitmap last-dance kernel_high readout

## Context

This note summarizes the final bounded diagnostic slice from:

- Task packet: `docs/workflow/tasks/active/TASK_20260507_011215_slab_bitmap_last_dance.md`
- Extraction artifact: `logs/TASK_20260507_011215_sumoff_lastdance_test_runner_extract_20260507_022415.txt`
- Kernel disassembly: `vmlinux.asm`
- Kernel image for symbolization: `riscv-linux/vmlinux`

The diagnostic only covers confirmed `PRIVATE_DATA` load/store traps recorded in the OpenSBI mediation path. The special "last dance" profile only counts traps whose saved trap-time `mstatus` has `SUM=0`.

## What `kernel_high` means

`kernel_high` is an address-shape bucket for the actual trap `fault_va` / access VA, not a semantic proof by itself.

The implementation in `opensbi/lib/sbi/sbi_trap_ldst.c` uses:

```c
fault_va < 0x0000800000000000 -> user_like_low
fault_va >= 0xffff800000000000 -> kernel_high
otherwise -> unknown
no access VA -> unavailable
```

Therefore, `kernel_high` means: the faulting virtual address was in the high-half kernel-shaped VA range. It does not mean "SUM=0 therefore kernel"; the label comes from the actual `fault_va` bucket.

In this run, every SUM=0 confirmed `PRIVATE_DATA` access VA was classified as `kernel_high`:

```text
private_total=159861
sumoff_total=131542
sumoff_load=110052
sumoff_store=21490
kernel_high=131542
user_like_low=0
unknown=0
unavailable=0
pc_overflow=10667
```

This is strong evidence that the dominant non-SUM traps are not low user-VA uaccess-wrapper accesses. They are high-VA kernel-side accesses to physical pages that are currently marked as `PRIVATE_DATA`.

## Key limitation

The current profile records:

- SUM=0 load/store totals.
- Whether access VA was available.
- Access-VA shape bucket.
- Owner metadata valid/missing totals.
- A bounded retained PC table and overflow.

It does not record:

- Concrete per-trap `fault_va`.
- Concrete per-trap `target_phys`.
- Concrete `origin_va`.
- Owner VA top buckets.
- Full call stack.

So this note can answer "which PCs/functions are touching `PRIVATE_DATA` through high kernel VAs" fairly well, but it cannot precisely answer "which page/object/region was touched" beyond broad attribution from existing aggregate context.

## vmlinux.asm mapping

Two retained symbols dominate.

### `__memcpy`

Symbol:

```text
ffffffff80a3af64 <__memcpy>
```

Source:

```text
linux/arch/riscv/lib/memcpy.S
```

Important disassembly region:

```text
ffffffff80a3afa0: ld a4,0(a1)
ffffffff80a3afa2: ld a5,8(a1)
...
ffffffff80a3afc0: ld t5,72(a1)
ffffffff80a3afc4: sd a4,0(t6)
...
ffffffff80a3afe8: sd t5,72(t6)
ffffffff80a3afec: ld a4,80(a1)
...
ffffffff80a3affc: ld t1,120(a1)
...
ffffffff80a3b03c: sw a4,0(t6)
```

Interpretation:

- PCs `0xffffffff80a3afa0..0xffffffff80a3affc` are the 128-byte unrolled copy load side. Traps here mean `memcpy` source address `a1 + offset` was a high kernel VA whose PA was tagged `PRIVATE_DATA`.
- PCs `0xffffffff80a3afc4..0xffffffff80a3afe8` are the corresponding store side. Traps here mean `memcpy` destination address `t6 + offset` was a high kernel VA whose PA was tagged `PRIVATE_DATA`.
- PC `0xffffffff80a3b03c` is the 4-byte tail store path.

Most retained `memcpy` traps are loads, which suggests the dominant pattern is kernel `memcpy` reading from a kernel mapping of protected pages. Some workloads also retain store-side `memcpy` traps.

### `update_vsyscall`

Symbol:

```text
ffffffff800b2f00 <update_vsyscall>
```

Source:

```text
linux/kernel/time/vsyscall.c
```

Important source behavior:

```c
struct vdso_data *vdata = __arch_get_k_vdso_data();
vdso_write_begin(vdata);
vdata[CS_HRES_COARSE].clock_mode = clock_mode;
vdata[CS_RAW].clock_mode = clock_mode;
vdso_ts = &vdata[CS_HRES_COARSE].basetime[CLOCK_REALTIME];
vdso_ts->sec = tk->xtime_sec;
vdso_ts->nsec = tk->tkr_mono.xtime_nsec;
...
WRITE_ONCE(vdata[CS_HRES_COARSE].hrtimer_res, hrtimer_resolution);
...
vdso_write_end(vdata);
```

Representative disassembly:

```text
ffffffff800b2f0c: lw a3,0(a4)
ffffffff800b2f14: sw a3,0(a4)
ffffffff800b2f18: sw a5,328(a4)
ffffffff800b2f2e: sw a7,4(a4)
ffffffff800b2f38: sd a5,32(a4)
ffffffff800b2f84: sd a5,136(a4)
ffffffff800b3018: sd a5,144(a4)
ffffffff800b305e: sd a5,216(a4)
```

Interpretation:

`update_vsyscall` updates kernel vDSO time data. If this appears in the SUM=0 `PRIVATE_DATA` profile, it means ordinary kernel time/vDSO maintenance touched a page that the blanket bitmap design considers private. This is a kernel-internal path, not a usercopy wrapper.

## Per-workload summary

All rows below are from the extraction artifact's final per-run summaries and retained PC symbolization.

| Run | Workload | SUM=0 total | Retained PC pattern | Immediate readout |
| --- | --- | ---: | --- | --- |
| 1 | `printf alpha >/dev/null` | `5634` | `memcpy=5634`, overflow `0` | All retained SUM=0 traps are `memcpy`; almost all are load-side. This is a simple workload, yet protected pages are read through high kernel VAs. |
| 2 | read `/etc/hostname` line | `6146` | `memcpy=6146`, overflow `0` | Same shape as run 1, slightly larger count. |
| 3 | fork/COW private string | `13480` | `memcpy=12290`, `update_vsyscall=1190`, overflow `0` | Fork/COW introduces visible `update_vsyscall` traffic in addition to `memcpy`. |
| 4 | `cat /etc/hostname` | `19054` | `memcpy=17206`, `update_vsyscall=1400`, overflow `448` | File/exec/mmap-style workload increases both `memcpy` and vDSO-time maintenance; some tail PCs are lost to bounded overflow. |
| 5 | `echo alpha | cat` | `27133` | `memcpy=23862`, `update_vsyscall=2759`, overflow `512` | Pipeline/fork/exec style workload amplifies the same two retained symbols. |
| 6 | `wc -c /etc/hostname` | `29284` | `memcpy=18287`, `update_vsyscall=1674`, overflow `9323` | Highest overflow. The overflow is store-heavy, so retained PC rows are not a reliable complete distribution for this run. |
| 7 | `echo alpha | wc -c` | `27223` | `memcpy=24431`, `update_vsyscall=2408`, overflow `384` | Similar to run 5; mostly retained `memcpy`, with visible `update_vsyscall`. |
| 8 | `nacc_shm_repro` | `3588` | `memcpy=3588`, overflow `0` | Shared-memory repro is much smaller than file/pipeline workloads and retained PCs are all `memcpy`. |

## Supporting aggregate context from raw QEMU logs

The raw QEMU dumps still include older all-`PRIVATE_DATA` aggregate stats. These are not SUM=0-only, so they should be used only as supporting context.

The dominant category is consistently:

```text
[SBI] PRIVATE_DATA category syscall_buffer_path
```

Examples:

```text
run 1: syscall_buffer_path total=7519, teardown_mapping_update total=21
run 4: syscall_buffer_path total=21068, teardown_mapping_update total=2173
run 8: syscall_buffer_path total=4663
```

Common sync reasons include:

- `invoke`
- `mmap`
- `mprotect`
- `fork`
- sometimes `exec`, `brk`, `munmap`

Common syscall buckets include:

- `nr=226 path=mapping_update` (`mprotect`)
- `nr=293 path=unknown` (`rseq`)
- `nr=135 path=unknown` (`rt_sigprocmask`)
- `nr=220/221 path=fork_exec` (`clone/execve` depending on run)
- `nr=0 path=unknown` (`read`)
- run-specific user-buffer/file-path calls such as `read`, `write`, `openat`, `readlinkat`

This suggests the protected PFNs are often touched while the process is inside syscall/mapping/fork/exec related activity. But because this aggregate is not SUM=0-only, it should not be used as proof that every retained `kernel_high` PC belongs to a specific syscall bucket.

## Main interpretation

The current blanket PFN bitmap approach protects whole Linux-managed user-data leaf regions while those physical pages remain visible through normal kernel mappings. The result is that normal kernel paths see the same physical pages through high kernel VAs and trigger `PRIVATE_DATA` traps with trap-time `SUM=0`.

The retained PCs show two concrete examples:

1. `__memcpy`: generic kernel copy logic reading/writing protected pages through high kernel addresses.
2. `update_vsyscall`: ordinary kernel vDSO time-data maintenance touching a protected page.

This supports the concern that the dominant trap surface is not naturally covered by TX-style usercopy wrapper reasoning. Usercopy TX wrappers explain low user-VA access contexts, but the dominant SUM=0 profile is high kernel VA access.

## Evidence / inference boundary

Observed facts:

- All eight workloads passed.
- Arithmetic checks passed.
- All SUM=0 confirmed `PRIVATE_DATA` access VAs classified as `kernel_high`.
- Retained PCs symbolize mostly to `__memcpy`; runs 3-7 also retain `update_vsyscall`.
- Runs 4-7 have bounded PC table overflow; run 6 has especially large overflow.
- Existing all-`PRIVATE_DATA` raw QEMU stats show dominant `syscall_buffer_path` and mapping/fork/exec related context.

Inferences:

- These are likely kernel-side/internal accesses to protected PFNs through kernel mappings.
- Blanket bitmap protection is exposing normal kernel maintenance/copy hotspots that are not well modeled as explicit uaccess-wrapper accesses.
- `update_vsyscall` implies at least some protected pages overlap with ordinary kernel-maintained vDSO/time data behavior under the current attribution/protection scheme.

Not proven by this data:

- The exact concrete fault VA or PA for each trap.
- Which exact user object/heap/stack/TLS/file page each trap belongs to.
- A safe allowlist.
- A safe unseal rule.
- A staging-buffer policy.
- A mediation policy change.

## If a next diagnostic is needed

A small follow-up profiler could answer the remaining "which region/page" question without per-trap printk:

- Add a bounded top-N table for `fault_va >> 12` or `origin_va >> 12`.
- Track per bucket: total/load/store, PC symbol bucket, access class, owner metadata valid/missing.
- Keep it SUM=0-only and confirmed `PRIVATE_DATA`-only.
- Avoid VMA/proc-map/ELF classification unless separately required.

This would make it possible to say whether `memcpy` and `update_vsyscall` are repeatedly touching the same owner pages, broad scattered pages, or specific mapping-lifecycle pages.
