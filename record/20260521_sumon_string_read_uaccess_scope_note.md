# SUM-On String-Read Uaccess Scope Note

Date: 2026-05-21

Status: design/reconciliation note only. This is not a code requirement and
does not authorize a repair route by itself.

## Why This Note Exists

The workload-1 SUM-on panic validation stopped at a PRIVATE_DATA load during
`sys_openat path=file_path`. The stop signature matched the prior
`do_strncpy_from_user` / `strncpy_from_user` attribution:

- QEMU line 1888: `[NACC][strict-sumon-first-deny]`
- QEMU line 1889: `[NACC][strict-sumon-panic]`
- `pc=0xffffffff804d2370`
- `ra=0xffffffff804d22fa`
- `trap_va=0x3fc0fd7bd0`
- `syscall=56`
- `path=file_path`
- `sum=1`
- `uaccess_active=0`
- `tx_active=0`

The important observation is not that `sys_openat` or `strncpy_from_user()` is
special. The important observation is that this is a string-read user-access
operation over a NaCC PRIVATE_DATA page, and the current NaCC uaccess context
does not cover that operation family.

## `strncpy_from_user()` Shape

The generic implementation is in `linux/lib/strncpy_from_user.c`.

The public wrapper:

- checks `count`
- checks address-space bounds with `TASK_SIZE_MAX` / `untagged_addr()`
- enters a user-read window with `user_read_access_begin(src, max)`
- calls `do_strncpy_from_user()`
- exits through `user_read_access_end()`
- returns length, `count`, or `-EFAULT`

Inside `do_strncpy_from_user()`, the actual reads are `unsafe_get_user()`
loads:

- word-at-a-time read first
- byte-at-a-time fallback after a fault or unaligned source/destination
- exception-table fixup turns a fault into the helper's `-EFAULT` return path

On RISC-V, `unsafe_get_user()` resolves through the `__get_user()` family in
`linux/arch/riscv/include/asm/uaccess.h`. That lower layer enables SUM,
executes the user load, and relies on exception-table fixup on fault.

This explains the earlier redirect-only weakness: if OpenSBI only redirects
or denies in a recoverable way, Linux can route the fault through uaccess
fixup and continue with `-EFAULT`. The panic validation corrected this at the
diagnostic layer by hard-stopping in OpenSBI.

## Existing NaCC Coverage Gap

NaCC already has useful uaccess diagnostics, but they do not currently cover
this string-read path.

Existing coverage:

- `copy_from_user()` / `copy_to_user()` have transaction begin/end logging in
  `linux/include/linux/uaccess.h`.
- `raw_copy_from_user()` / `raw_copy_to_user()` have
  `nacc_private_data_uaccess_enter()` / `nacc_private_data_uaccess_exit()` in
  `linux/arch/riscv/include/asm/uaccess.h`.
- `get_user()`, `put_user()`, and `clear_user()` have explicit transaction
  classes in the RISC-V uaccess header.

Gap:

- `strncpy_from_user()` and `strnlen_user()` are generic string helpers.
- They do not go through `raw_copy_from_user()`.
- They use `user_read_access_begin()` plus `unsafe_get_user()` loops.
- The current NaCC transaction enum has copy/get/put/clear classes, but no
  string-read class.

That matches the panic line's `uaccess_active=0 tx_active=0`: the operation is
semantically uaccess, but it is outside the current NaCC uaccess accounting
surface.

## Recommended Abstraction Level

The next repair should not be a `sys_openat` policy and should not be a
callsite-specific `strncpy_from_user()` exception. A better abstraction is an
explicit NaCC uaccess operation scope:

```c
nacc_uaccess_scope_begin(class, direction, user_va, max_len, caller);
...
nacc_uaccess_scope_end(result);
```

The policy-relevant fields should be operation-level, not syscall-level:

- operation class
- direction
- user VA
- maximum byte window
- current task key / root
- caller PC for attribution
- nesting or transaction identity
- result on exit

OpenSBI should keep default-deny behavior for S-mode SUM-on PRIVATE_DATA traps.
It should only service or authorize a trap when it matches an active explicit
scope:

- same task/root context
- matching direction
- faulting VA inside the declared `[user_va, user_va + len)` window
- access width contained in the remaining window
- compatible operation class

Syscall/path metadata should stay diagnostic only. `path=file_path` helps
explain why the string read happened, but it should not become policy
authority.

## Operation Families

A useful first taxonomy:

- `STRING_READ`: `strncpy_from_user()`, `strnlen_user()`
- `BULK_READ`: `copy_from_user()`, `raw_copy_from_user()`
- `BULK_WRITE`: `copy_to_user()`, `raw_copy_to_user()`
- `SCALAR_READ`: `get_user()`
- `SCALAR_WRITE`: `put_user()`
- `ZERO_TO_USER`: `clear_user()`
- `UNSAFE_READ_BLOCK`: direct `user_read_access_begin()` +
  `unsafe_get_user()` loops that are not known string reads
- `USER_ATOMIC`: futex/atomic user operations, likely separate follow-up

Workload 1's stop point should be treated as a `STRING_READ` example, not as a
one-off filename helper patch.

## Candidate Constraint Points

### 1. Generic String Helpers

Instrument `strncpy_from_user()` and `strnlen_user()` as `STRING_READ` scopes.

Pros:

- semantically accurate
- covers the observed workload-1 failure
- avoids patching each syscall or caller
- small enough for a first validation slice

Cons:

- still leaves other `user_read_access_begin()` users uncovered
- requires a broader taxonomy before workload expansion

### 2. `user_read_access_begin()` Wrappers

Create NaCC-aware wrappers around `user_read_access_begin()` /
`user_read_access_end()` that carry an explicit operation class.

Pros:

- captures the common high-level uaccess window shape
- can cover string helpers and other unsafe access blocks

Cons:

- the raw macro only knows pointer/length, not operation semantics
- blindly authorizing every `user_read_access_begin()` would be too broad
- needs explicit class-bearing wrappers to avoid losing meaning

### 3. Low-Level `unsafe_get_user()` / `__get_user()`

Use the low-level load as an enforcement check only.

Pros:

- sees the exact faulting load
- good for final range/width verification

Cons:

- too low-level to decide authorization by itself
- does not know whether the load is string, scalar, bulk, atomic, or something
  else
- would recreate an implicit fallback if it became the primary allow point

### 4. Syscall/Path Category

Keep `sys_openat path=file_path` as attribution only.

Pros:

- useful for debugging and grouping evidence

Cons:

- too coarse and policy-unsafe
- would bind authorization to Linux syscall names instead of operation
  semantics
- not reusable for shared helper paths

## Suggested First Repair Slice

If this becomes an implementation packet, the first slice should be narrow but
class-shaped:

1. Add a `STRING_READ` uaccess transaction/scope kind.
2. Wrap `strncpy_from_user()` and possibly `strnlen_user()` with that scope.
3. Preserve `syscall/path` as diagnostics.
4. Keep OpenSBI default-deny for unmatched SUM-on PRIVATE_DATA traps.
5. Allow or diagnose only traps matching the active `STRING_READ` scope.
6. Re-run only workload 1 first.

This would test the abstraction without turning the repair into per-syscall or
per-caller patching.

## Open Design Questions

- Should the first version only record `STRING_READ` scopes, or should OpenSBI
  also allow matching traps under that scope?
- Should `strnlen_user()` be included in the same first slice, given that it
  has the same `user_read_access_begin()` + `unsafe_get_user()` shape?
- How should nested scopes interact with the existing `copy_from_user()` /
  `get_user()` transaction diagnostics?
- Should operation classes be authorization classes, diagnostic classes, or
  both?
- What is the exact allow rule for partial word reads near the declared window
  boundary?
- How should pagefault-disabled nofault variants be represented?

## Boundary

This note intentionally does not choose the final explicit uaccess interface.
It records why the next repair should be operation-family based and why the
workload-1 stop should not become a one-off `strncpy_from_user()` or
`sys_openat` patch.
