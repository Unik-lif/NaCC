# T5.1 Uaccess-Loop Feasibility Closeout

Generated: 2026-05-04

Scope: May 3-4, 2026 uaccess-loop feasibility marathon for
`fallback_scalar_usercopy` / `__asm_copy_from_user` / `__asm_copy_to_user`.

Primary source packet: `record/user_copy_task_packet.md`

Main campaign: `docs/workflow/tasks/active/TASK_20260503_011553_marathon_user_copy.md`

## Executive Verdict

The broad uaccess-loop mediation target should be parked for now.

The current evidence is useful and mostly converged, but it is not favorable
for a broad performance-optimization portal. The clean active-wrapper subset is
real, but broader workload evidence shows fragmented loop states, missing
wrapper context, missing attribution ranges, and nested/non-loop reporting
effects. These are security boundary facts, not just logging noise.

Recommended decision:

- No broad eight-workload validation is needed before discussion.
- Do not start a broad `fallback_scalar_usercopy` mediation prototype now.
- If a prototype is still desired later, scope it as a narrow mechanism demo:
  active wrapper only, direction known, bounded range known, PFN owner exact,
  CID match yes, and fail-closed for every other state.
- For performance work, pick a target with a clearer semantic boundary and a
  shorter validation loop.

## What Changed From The Earlier Optimistic View

The May 2 closer report made the raw-uaccess path look promising because the
active-wrapper subset was exact and direction-heavy:

- active raw-uaccess: `11,054 / 183,878 = 6.0%`
- `to_user`: `8,243 / 11,054 = 74.6%`
- the common raw uaccess abstraction unified many caller paths

The May 3-4 work answered a different and more important question: whether the
broader MEPC-family hotspot itself has enough recoverable state to mediate
safely. That answer is much less favorable.

## Static / Instrumentation Result

The instrumentation work established that:

- RISC-V `__asm_copy_from_user` and `__asm_copy_to_user` share the same
  low-level assembly body around `fallback_scalar_usercopy`.
- Linux wrapper context can provide direction, original user/kernel bases,
  length, caller, and loop bounds.
- OpenSBI can classify trap-time loop events by wrapper activity, direction,
  range membership, PFN attribution, and recovery state.
- MEPC is useful as a reporting denominator, but it is not policy authority.

This part was successful. The problem is not that the instrumentation cannot
see anything. The problem is that once the denominator is broadened, too many
important events are not mediation-safe.

## Clean T0 / Workload-2 Shape

The repaired T0 run and workload 2 showed a clean shape:

- `loop_mepc=753`
- `active_wrapper_yes=753`
- `active_wrapper_no=0`
- `recoverable=720`
- `unrecoverable=33`
- `direction_from_user=194`
- `direction_to_user=559`
- `direction_unknown=0`
- `recoverable_over_broad_bp=9561`

Interpretation:

This proves the reporting model works for a simple active-wrapper workload.
It also proves there is a real recoverable subset that could support a very
narrow fail-closed mechanism demo.

It does not prove the broad uaccess-loop family is a good performance target.

## Workload-6 Breaks The Clean Shape

The workload-6 command, `wc -c /etc/hostname; echo done`, completed with code 0
but exposed the key negative signal:

- `loop_mepc=3171`
- `active_wrapper_yes=2039`
- `active_wrapper_no=1132`
- `recoverable=1557`
- `unrecoverable=1614`
- `direction_unknown=1132`
- `UNRECOVERABLE_NO_WRAPPER_CONTEXT total=1132`
- `UNRECOVERABLE_EXCEPTION_FIXUP_CONTEXT total=64`
- `UNRECOVERABLE_PFN_OWNER_MISSING` grew up to `482`

Useful ratios from that final snapshot:

- no-wrapper loop activity: `1132 / 3171 = 35.7%`
- recoverable loop activity: `1557 / 3171 = 49.1%`
- unrecoverable loop activity: `1614 / 3171 = 50.9%`
- owner-missing among active-wrapper loop rows: `482 / 2039 = 23.6%`

Interpretation:

This is the main reason to park the broad portal. The workload did not fail,
but the mediation candidate became fragmented. About half of the loop
denominator is not recoverable under the current safe authority model, and a
large no-wrapper slice has unknown direction/range.

## Source Mapping Of Suspicious Rows

The workload-6 mapping child clarified that the suspicious rows were not random
parser artifacts.

Real inactive scalar-loop stores:

- `ffffffff80a21842`: `fallback_scalar_usercopy`, pre-alignment byte store
- `ffffffff80a218c2`: `fallback_scalar_usercopy`, shift-copy word store
- `ffffffff80a218d6`: `fallback_scalar_usercopy`, tail byte store

These are real raw-copy-loop instructions, but they appeared without active
Linux wrapper context. Without wrapper context, direction/range recovery cannot
be made safe.

Historical non-loop clear-page family:

- `ffffffff80a20a02` maps to `linux/arch/riscv/lib/clear_page.S`, not to the
  raw uaccess loop.
- It was observed under still-active `copy_to_user` context near syscall 221 /
  exec-stack setup, but the fault address was outside the user-copy range.

The reporting repair separated this class from raw-loop evidence. Later
diagnostics found that Linux-local page zeroing for the exec-stack case happened
before the page was installed as a PRIVATE_DATA user mapping, so it did not
produce an OpenSBI-counted active-context non-loop trap in the repaired runs.

## PFN Owner / CID Confidence

The PFN-owner confidence repair improved reporting, but did not make the target
safe enough for broad mediation.

The bounded workload-6 runtime proof showed:

- workload completed with code 0
- aggregate PFN-owner and CID fields are emitted and countable
- `owner=PRIVATE_DATA total=2039`
- `owner=UNKNOWN total=482`
- `owner_missing_reason=root_absent total=0`
- `owner_missing_reason=range_absent total=482`
- `owner_missing_reason=ambiguous total=0`
- `origin_confidence=exact total=1557`
- `origin_confidence=missing total=482`
- `cid_match=yes total=2039`
- `cid_match=no total=0`
- `cid_match=unknown total=0`

Interpretation:

CID reporting is now good enough to stop treating every row as unknown. But the
remaining `482` owner-unknown events are range-attribution gaps. They must stay
fail-closed and should not be mediated.

## Operational Phenomena

The marathon also spent time on validation workflow problems:

- early runs hit SSH / auto-run readiness problems after Linux boot
- some debug-batch windows or QEMU image owners had to be handled by bounded
  test-runner cleanup
- amplification attempts around workload 6 produced timeouts or coverage gaps
  rather than a clearer feasibility answer

These were useful for hardening the workflow, but they are not the decisive
technical reason to stop. The decisive technical reason is the fragmented
recoverability and ownership picture once workload 6 is included.

## Performance-Optimization Interpretation

For performance work, the current target is unattractive:

- The common MEPC family is hot, but hotness does not imply safe mediation.
- The clean active-wrapper subset is much smaller than the broad hotspot.
- The recoverable subset is not stable across workloads.
- Broad mediation would need many exclusions and special cases.
- Every exclusion is a fail-closed path, which reduces expected payoff.
- Continuing to chase edge cases is likely to produce more detail, not a clean
  optimization boundary.

This is a classic sign that the task has shifted from performance engineering
into a broad semantic survey. The survey has produced a useful negative result.

## Recommended Next Step

Stop this marathon as a broad feasibility campaign and discuss the next
performance target.

Possible follow-ups:

1. Write a short human-facing final report from this closeout and archive the
   active marathon packets.
2. Open a new, smaller performance-target-selection packet that compares trap
   families by semantic clarity, expected payoff, and validation cost.
3. If a uaccess demo is still valuable, define it explicitly as:
   active-wrapper only, owner-exact only, CID-match only, direction-known only,
   bounded-range only, with all other rows fail-closed and excluded from payoff
   claims.

The broad `fallback_scalar_usercopy` portal should not be the main next
engineering bet.
