You are helping plan the next implementation stage of **NaCC**, a RISC-V confidential container system built from customized **Linux**, **OpenSBI (M-mode secure monitor)**, a **NaCC agent**, and customized **QEMU**.

Your task is **not** to redesign the whole system from scratch.
Your task is to plan the next mainline implementation step based on the current architecture decisions below.

---

# 1. Project positioning

NaCC is **container-first**, not process-first and not enclave-first.

The protection unit is a **confidential container instance (CID)**, not each process inside the container.

The current threat model is:

* Linux / Host OS is not fully trusted
* OpenSBI monitor is trusted
* the NaCC agent participates in controlled runtime / trap handling
* cross-container unauthorized access matters
* same-container parent/child fine-grained confidentiality is currently **out of scope**
* generic shared memory is currently **out of scope**
* same-CID fork inheritance is allowed as a controlled exception

Do **not** drift into a per-process TEE design.

---

# 2. Current true state

Assume the following are already true:

* fork+exec is already working on the intended native path
* the active design no longer depends on old bulk-style fork
* the active exec path no longer depends on transfer_ptp
* Linux-native fork/read/walk/accounting paths are preferred
* direct secure PTP construction is already in place for the main exec direction
* secure PTP role pinning is already implemented for upper-level secure page table pages (e.g. secure L1/L2 PTP pages)
* those secure PTP pages are already protected via PMP-style mechanisms and Linux cannot directly write them

Treat older notes claiming fork+exec is blocked as stale.

---

# 3. Important architecture boundary

We have now converged on the following design boundary.

## 3.1 Secure PTP pages

Do **not** plan to protect secure page table pages using bitmap.

Reason:

* secure PTP pages already have stronger structural protection
* they are already role-pinned and protected in a PMP-controlled region
* Linux may read but must not write them

So the bitmap discussion is **not** about those pages.

## 3.2 The bitmap target set

The current bitmap focus is only:

1. **L0 root page table pages**
2. **user data pages**

These two are not handled in the same way.

---

# 4. L0 root page rule

L0 root pages are special objects.

They must be distinguishable from normal user data pages.

Reason:

* an L0 root page is not a normal secure PTP page
* its upper half corresponds to the kernel half and must remain writable by Linux
* its lower half corresponds to the user half and must not be freely modified by Linux

Therefore:

* we want a small bitmap/tag to identify that a PFN is an **L0 root page**
* when Linux writes such a page, the check must be **offset-based**
* the monitor/MMU-side logic should distinguish the written PTE slot:

  * upper half / kernel half: writable
  * lower half / user half: must be blocked or routed through controlled checks

Do **not** propose a full “make the whole L0 page read-only” design.
The key point is **partial control by slot/offset**, not whole-page immutability.

---

# 5. User data page rule

For now, private user data pages are treated with a much simpler policy.

Current design decision:

* default assumption: **no sharing**
* we do **not** currently care about fine-grained same-container parent/child confidentiality
* same-CID fork inheritance is allowed
* generic sharing is deferred
* if future sharing is needed, it should be explicitly managed by the agent / controlled path rather than assumed by default

Because of that, we currently **do not want**:

* per-page owner CID tables
* per-page mm tracking
* per-page refcount
* full COW/shared metadata
* full VMA mirroring inside the monitor

Instead, user data page tracking should stay lightweight.

---

# 6. Bitmap model currently preferred

We currently prefer a **small bitmap / tiny per-page state** approach.

A 1-bit design is considered insufficient because L0 needs to be distinguished from normal user data pages.

A 2-bit state is the currently preferred direction, for example:

* 00 = NORMAL
* 01 = ROOT_L0
* 10 = PRIVATE_DATA
* 11 = RESERVED

This is only an example encoding.
You may refine the exact encoding if needed, but keep the model **small and minimal**.

Important:

* secure PTP pages are not the bitmap target here
* bitmap is for L0 and user data pages only

---

# 7. Sharing / fork rule

Current policy:

* a page marked as confidential/private is assumed **non-shared by default**
* the main exception is **same-CID fork inheritance**
* we do not need to fully model parent/child isolation
* we do not need generic shared memory now

This means:

* default rule: confidential/private pages should not be reused/shared arbitrarily
* controlled rule: a same-CID fork path may be allowed to inherit a private page mapping

Do not over-design this into a rich page-level ownership system.

---

# 8. Lifecycle rule

The lifecycle should be managed **coarsely**, not per-page with complex ownership accounting.

We currently prefer:

* no page-level fine-grained refcount/reuse accounting
* no heavy ownership metadata
* no attempt to reclaim private pages precisely at every single mm event
* instead, lifecycle checks should be tied to controlled monitor-visible events
* container/CID-level or coarse mm-family-level handling is preferred over per-page fine-grained accounting

In particular:

* secure monitor checks should happen on relevant slow paths
* do not design a solution that puts heavy logic into hot-path ordinary memory accesses

---

# 9. What I want from you

Please produce a **planner-grade architecture/implementation plan** for the next step, focusing on:

## A. Mapping orchestration

How the monitor-side and Linux-side logic should cooperate when:

* a confidential container is registered
* an L0 root page is marked
* a secure leaf mapping is installed for a user data page
* a same-CID fork duplicates or inherits a mapping
* an mm or container lifecycle event happens

I want a concrete plan for the **mapping orchestration**, not vague security commentary.

## B. Minimal metadata design

Given the design above, define:

* what exact bitmap/tag states are needed
* what each state means
* which objects are covered by the bitmap
* which objects are explicitly out of bitmap scope

## C. Event-to-action mapping

For each relevant event, explain:

* trigger
* required checks
* state transition or no transition
* whether Linux is allowed, blocked, or must go through a controlled path

Relevant events include at least:

* confidential container registration
* root L0 tagging
* Linux write to L0 page
* secure leaf install of a user data page
* same-CID fork duplication
* mm teardown
* CID/container teardown

## D. Mappings data structure planning

This is important.

Please think carefully about what **mappings** should exist, and at what granularity.

I specifically want you to propose a practical plan for:

* what mapping records the monitor should maintain
* whether mappings should be per-CID, per-mm-family, or another coarse grouping
* what information a mapping entry must minimally contain
* how those mappings are created, updated, and retired
* how they are used during checks
* how to avoid turning the monitor into a full Linux MM shadow

You must keep the mappings design **minimal**, but still operationally useful.

## E. Explicit non-goals

List what we are **not** doing in this stage, so the implementation does not sprawl.

---

# 10. Constraints you must obey

* preserve Linux-native behavior as much as possible
* do not redesign Linux allocation into a special monitor-only data pool mainline
* do not introduce heavy per-page rich metadata
* do not mirror full Linux VMA semantics in the monitor
* do not redesign the project into a process-level enclave/TEE system
* keep secure PTP out of the bitmap scope
* remember that L0 handling is offset-sensitive / partial-writable
* remember that same-CID fork inheritance is allowed
* keep the design practical for implementation, not just elegant on paper

---

# 11. Output format I want

Please answer in the following structure:

1. **Restated design boundary**
2. **Bitmap scope and exact state model**
3. **Mapping orchestration plan**
4. **Minimal mappings metadata design**
5. **Event-by-event control flow**
6. **What checks belong in MMU/monitor vs Linux vs agent**
7. **Lifecycle / teardown plan**
8. **Main implementation risks**
9. **Recommended next coding steps in priority order**

Be concrete.
Challenge weak assumptions if needed, but stay within the design direction above unless you have a very strong reason not to.
