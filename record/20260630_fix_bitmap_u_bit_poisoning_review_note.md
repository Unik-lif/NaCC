# NaCC bitmap sweep review note: U-bit poisoning boundary

Date: 2026-06-30

This note records a human review concern for
`TASK_20260630_000006_fix_bitmap`.

## Short concern

The current repair makes OpenSBI independent of Linux's `_PAGE_NACC` /
`PTE_NACC` hint for eligible protected user leaves. If OpenSBI observes an
ordinary resident 4 KB `PTE_U` leaf in the protected lower-256 VPN2 scope, the
late pre-Agent sweep can force `PTE_NACC` and acquire `PRIVATE_DATA` bitmap
ownership even when Linux omitted the hint.

That closes the `_PAGE_NACC` hint-omission gap, but it does not fully close a
stronger malicious-Linux classification attack:

> Linux may clear `PTE_U` on a leaf that is semantically user data, causing the
> monitor to classify it as non-user/supervisor during the sweep and skip
> bitmap acquisition.

In this threat model, VMA metadata cannot be used as a trusted fallback because
it is also Linux-controlled. `PTE_U` is only a hardware-access classification
at the instant of the sweep; it is not a trustworthy statement that the leaf is
not user data.

## Desired security direction

For a stronger malicious-Linux claim, the protected user VA scope should not
silently accept ordinary resident leaves just because `PTE_U` is absent.

A conservative fail-closed policy would be:

- ordinary resident 4 KB leaf with `PTE_U`: force/acquire `PRIVATE_DATA`;
- ordinary resident 4 KB leaf without `PTE_U`: reject the handoff unless it is
  an explicit monitor-approved exception;
- protected-scope huge leaf: reject unless range acquisition is implemented;
- Secure PTP, Agent aperture, special/devmap, and PROT_NONE/nonresident cases:
  handle through explicit rules rather than treating Linux classification as
  security authority.

The key review boundary is:

> The current patch removes Linux authority over `PTE_NACC` hint selection, but
> still implicitly relies on Linux not hiding user data by clearing `PTE_U`.
> If the paper/security claim includes malicious Linux at that level, missing
> `PTE_U` on an ordinary resident leaf in the protected user VA scope should
> become fail-closed behavior, not a silent skip.
