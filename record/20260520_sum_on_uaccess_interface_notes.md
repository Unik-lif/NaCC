# SUM-On Uaccess Interface Notes

Date: 2026-05-20

This note captures planner-side design context before filling
`TASK_20260520_141343_all_workloads_sum_on`. It is background for future
abstraction work, not a current code requirement.

## Problem Framing

NaCC private bitmap protected pages are not normally readable or writable by
Linux. The current OpenSBI private-data trap path made bring-up possible by
servicing Linux-origin private-data access traps, including SUM-on uaccess
cases. That implicit fallback is not the desired final security model: Linux
should not be able to get private data read or written merely by triggering a
trap.

SUM-bit-off behavior for workloads 1-8 is considered mostly converged. The
next question is how to approach SUM-bit-on private-data access without
falling into one-off fixes for every Linux helper.

## Current Understanding

The secure convergence target is not just performance optimization. The first
security goal is to replace or constrain implicit fallback with explicit NaCC
semantics.

A direct function-by-function route is risky because the Linux uaccess surface
is large and semantically varied: bulk copy, scalar get/put, clear/zero, string
copy, unsafe access blocks, rseq-style writes, and futex atomics do not all
share one clean copy contract.

The better route is to first use a strict-deny or deny-first diagnostic mode,
similar in spirit to the SUM-off convergence route:

- Make unauthorized S-mode private-data access traps visible or denied instead
  of silently serviced.
- Run a narrow workload and observe where SUM-on private-data handling stops.
- Use preserved evidence to group failures into a smaller abstraction.
- Avoid fixing a single high-level helper unless the evidence shows it is the
  representative insertion point for a broader access shape.

## Likely Abstraction Families

These families are current mental scaffolding only. Do not encode them into
the immediate task packet or code as mandatory classes.

- bulk copy from user
- bulk copy to user
- clear or zero to user
- scalar read and scalar write
- string read
- atomic or futex user operation
- nested non-uaccess work observed while a uaccess context is active

The important distinction is that safety convergence can be unified by
requiring explicit authorization or explicit operation semantics for
private-data access, while performance-oriented mediation may still need
per-family handling.

## Evidence Needed For Future Grouping

OpenSBI-side diagnostic evidence should support an attribution chain like:

`syscall/path -> uaccess caller -> faulting MEPC -> access type/width -> private PFN/tag`

Useful fields include:

- hart id
- cause
- fault VA and, if resolved, physical address, PFN, and PFN tag
- MEPC and RA
- access type: load, store, atomic, or unknown
- access width if decodable: 1, 2, 4, 8, or unknown
- saved SUM state
- SATP/root
- NaCC state
- current/task key, pid, cid if available
- syscall number and path category if available
- uaccess context if active: direction, user VA, length, caller PC
- transaction context if active
- deny reason

Full Linux stack unwinding is not required as a first step. A cheaper
attribution chain using syscall/path, uaccess caller, MEPC, RA, and sampled
registers should be enough to form the first buckets. If a bucket remains
ambiguous, add a narrow Linux-side diagnostic later.

## Current Suggested First Runtime Step

Run only canonical workload 1 first and preserve artifacts. The immediate goal
is to identify the first SUM-on private-data cause or confirm that workload 1
does not exercise the relevant failure under the current tree. Do not broaden
to workloads 2-8 until workload 1 evidence is reduced.
