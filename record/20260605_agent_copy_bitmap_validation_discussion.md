# Agent Copy and Bitmap Validation Discussion

Date: 2026-06-05

## Context

We discussed whether NaCC should move some private bitmap validation or `copy_from_user`-style private uaccess work out of OpenSBI and into Agent.

The original motivation was that OpenSBI currently feels heavy: for monitor-mediated private uaccess, it may need to resolve a Linux virtual address through software page-table walking, obtain the PFN, inspect the private bitmap tag, and then perform the copy. Since QEMU already enforces private bitmap tags in parts of the MMU translation path, we explored whether Agent could use normal virtual-address access and avoid explicit OpenSBI page-table walking.

## Important Observations

Agent can use the MMU to access a virtual address, but standard RISC-V does not provide a clean interface for Agent to ask the MMU for the translated PFN/tag.

This creates a hard split:

- If Agent has the same access rights as Linux, Agent cannot access private pages either, so moving copy work to Agent adds little.
- If Agent has stronger access rights than Linux and can always access private pages, then Agent becomes a trusted bypass. The copy may work, but the bitmap check is no longer automatically meaningful.
- A useful middle ground would require explicit QEMU/hardware semantics such as an Agent copy mode where QEMU checks bitmap tags internally based on operation/range/direction. That is possible to simulate, but it is another custom mechanism and needs stronger justification.

Because Agent cannot naturally obtain PFN/tag from the MMU, Agent-copy does not automatically remove the validation problem. It only removes OpenSBI page-table walking if the design is changed so access success itself is the validation result.

## Teacher Questions and Current Answers

Why not let Linux directly copy?

Linux should not have direct access to private pages. If Linux can freely copy private container memory, the bitmap isolation boundary against Linux is weakened.

Why not keep OpenSBI doing it?

OpenSBI is the cleanest policy owner because it owns canonical metadata and can validate PFN tags explicitly. The downside is that M-mode does not naturally reuse S-mode address translation results, so OpenSBI currently needs software page-table walks before PA-based copy.

What is the benefit of Agent?

The benefit is not yet proven. Agent only helps if it either:

- avoids OpenSBI software PTW through a well-defined access-based validation mode,
- performs naturally large or asynchronous data-plane work,
- or reduces M-mode workload without adding a longer control path.

For `copy_from_user`, the benefit is weak because the operation is synchronous, fault/COW-sensitive, and tightly coupled to Linux fault handling.

## Control-Flow Discussion

We also discussed whether the existing `acall`/`aret` and `CSR_TRAMPOLINE` mechanism could support Agent-mediated copy.

The current mechanism appears to be a simple single-continuation Agent/Linux switch:

- Agent receives a user trap.
- Agent forwards into Linux using `acall`.
- Linux handles syscall/page fault/exception.
- Linux returns to Agent using `aret`.

This model is not robust enough for nested service work such as:

- Linux enters Agent for copy.
- Agent faults while touching user VA.
- Linux must resolve page fault or COW.
- Agent must resume the partially completed copy.

If this direction is revisited, the cleaner design is not to add a separate instruction family. Instead, keep `acall`/`aret` as the single cross-domain portal and replace the single-slot trampoline continuation with a typed frame ABI. However, this redesign should not be started until Agent-copy has a clear semantic purpose.

## Current Conclusion

Do not make Agent-copy or Agent bitmap validation the main route for now.

The most defensible current design remains:

- OpenSBI is the policy authority and canonical bitmap/tag metadata owner.
- OpenSBI performs PFN/tag validation when exact bitmap semantics are required.
- Agent should not be inserted into `copy_from_user` hot paths unless it has a clear semantic or performance advantage.
- QEMU/hardware translation-assist or Agent copy modes should not be added just to avoid OpenSBI PTW without a stronger justification.

The concern that Agent is underused is valid, but using Agent purely for synchronous private uaccess may not be the right answer. Agent is more plausible for future work that needs an independent trusted runtime, controlled context transitions, larger-granularity services, or mechanical execution after OpenSBI authorization.

## Follow-Up Questions

- Is OpenSBI software page-table walking actually the dominant cost in private uaccess, or are trap/copy/fault paths larger contributors?
- Can OpenSBI reduce repeated walks with short-lived validation/cache structure without weakening security?
- Are there Agent responsibilities that are naturally asynchronous or coarse-grained enough to justify an extra control path?
- Should the `CSR_TRAMPOLINE` mechanism be redesigned independently as a typed frame ABI for future Agent/Linux interactions?

