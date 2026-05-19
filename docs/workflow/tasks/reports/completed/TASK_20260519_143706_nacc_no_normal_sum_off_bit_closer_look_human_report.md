# Human Progress Report

- Task ID: TASK_20260519_143706_nacc_no_normal_sum_off_bit_closer_look
- Task Packet: `docs/workflow/tasks/active/TASK_20260519_143706_nacc_no_normal_sum_off_bit_closer_look.md`
- Created: 2026-05-19 14:37:06 +0800
- Purpose: cumulative human-readable updates appended by coder, reviewer, and log_analyzer
- Append Rule: add a new timestamped section for each new turn; do not rewrite older entries
- Reading Hint: newest updates are appended at the end of this file

## 2026-05-19 17:48:34 +0800 planner/coder closeout

- Workload 3 diagnostic confirmed that the failing action can be understood at the page-copy primitive level: Linux reaches `copy_mc_user_highpage(to, from, vaddr, vma)` / inlined `__memcpy` with `from` pointing at a NaCC private source PFN.
- The temporary Linux `cow-sniff` patch was removed before closeout; it was diagnostic-only and should not be committed.
- OpenSBI strict-deny evidence plus `addr2line -i -f` is sufficient for the next repair direction: focus on the low-level private-source page-copy boundary rather than chasing more `do_wp_page()` predicates.
- Closeout note written to `record/20260519_nacc_cow_private_copy_sniff_closeout.md`.
