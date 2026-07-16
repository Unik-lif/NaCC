# NaCC Scalar get_user and String Bulk Uaccess Plan

Date: 2026-05-24

Status: design/planning note. The immediate iteration should only implement
the scalar private `get_user` repair needed by the rseq failure unless a later
task packet explicitly expands scope.

## Why This Note Exists

The profiling cleanup exposed a private-data user-access gap that was likely
hidden by the old context/profiling machinery. The fresh workload-1 failure
does not overlap directly with the earlier `strncpy_from_user()` string-read
scope work.

Observed chain:

```text
sys_rseq(rseq=0x3f83fa8800, len=0x20)
  -> rseq_set_notify_resume()
  -> syscall exit handles _TIF_NOTIFY_RESUME
  -> resume_user_mode_work()
  -> __rseq_handle_notify_resume()
  -> rseq_ip_fixup()
  -> rseq_get_rseq_cs()
  -> get_user(ptr, &t->rseq->rseq_cs)
```

The denied address `0x3f83fa8808` matches `struct rseq::rseq_cs`, which is an
8-byte scalar user read at offset 8 from the registered rseq base. The normal
RISC-V `get_user()` path reaches NaCC's private get-user SBI ecall, but the
OpenSBI side currently requires an active `STRING_READ + FROM_USER` scope.
rseq has no such begin/end scope, so OpenSBI returns `SBI_EDENIED`.

## Long-Term Shape

The user-access model should split scalar reads from string/bulk reads instead
of forcing both through the same string scope.

```text
scalar get_user:
  Linux get_user
    -> NACC scalar-read ecall
    -> OpenSBI checks SUM/task/root/private/page/width
    -> returns 1/2/4/8 bytes

string read:
  strncpy_from_user
    -> NACC string-scope begin
    -> NACC string/bulk-read helper
    -> OpenSBI validates and reads by range/page/chunk
    -> scope end
```

The scalar path should be a one-shot semantic operation. It should not require
a Linux-side begin/end scope because many legitimate kernel ABI metadata reads
have no natural scope lifecycle.

The string path can continue to use explicit scope because it is a range-based
operation. Later optimization should avoid per-character `get_user -> ecall ->
scope lookup -> page walk` by adding a string/bulk helper. OpenSBI should copy
authorized data into a normal Linux kernel buffer rather than exposing private
pages for direct Linux reads.

## Immediate Phase: Scalar Private get_user

The first implementation phase should be narrow:

- Preserve the profiling cleanup and do not restore syscall/category/uaccess
  bucket machinery.
- Preserve existing `strncpy_from_user()` / `strnlen_user()` string scope
  behavior.
- Do not add rseq-specific begin/end scope around `rseq_get_rseq_cs()`.
- Treat `SBI_EXT_NACC_UACCESS_PRIVATE_GET_USER_READ` as a one-shot scalar
  read for 1/2/4/8-byte user accesses.
- Keep OpenSBI as the final authority for private-data reads.

The OpenSBI scalar read checks should remain conservative:

- caller came from S-mode
- SUM is set
- current task key and SATP root are valid
- user VA resolves under the current root
- resolved PFN is tagged `NACC_PFN_TAG_PRIVATE_DATA`
- width is 1, 2, 4, or 8 bytes
- access does not cross a page

If those checks pass, OpenSBI can return the scalar value. If the address is
not private data, Linux should fall back to the normal `get_user` path as it
does today for `SBI_ERR_NOT_SUPPORTED`.

## Later Phase: String/Bulk Read

A later task can optimize string reads. A likely route:

- Keep `nacc_uaccess_scope_begin/end()` for operation intent and range.
- Add a dedicated string/bulk read ecall or helper used by
  `strncpy_from_user()` / `strnlen_user()`.
- Validate the range against the active scope in OpenSBI.
- Read by page or chunk, including NUL handling for string helpers.
- Return enough information for Linux to preserve normal helper semantics
  such as copied length, NUL termination, and `-EFAULT`.

The string/bulk work should not be coupled to the rseq repair.

## Non-Goals

- Do not blanket-allow SUM-off private-data loads.
- Do not weaken coredump strict SUM-off policy as a way to hide the rseq
  scalar-read failure.
- Do not restore removed profiling context feeds or bucket tables.
- Do not introduce a Linux-only trust flag that bypasses OpenSBI policy.
