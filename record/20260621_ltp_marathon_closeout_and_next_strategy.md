# LTP Marathon Closeout And Next Strategy

Date: 2026-06-21

Task: `TASK_20260620_222557_ltp_fix`

## Outcome

The LOG-enabled LTP marathon was stopped by human decision after roughly one
day. It was productive as a fault-discovery and harness-hardening run, but it
was too slow and too confounded to remain the default broad-coverage strategy.

The task should be treated as closed evidence, not as an unfinished full-LTP
campaign to resume automatically.

## What Worked

The task produced two useful narrow Linux repair boundaries:

- The `abort01` coredump/private-data-load path was repaired and focused
  validation showed the blocker no longer recurred.
- The Secure PTP `move_page_tables()` / `move_normal_pmd()` PMD clear path was
  repaired by routing the Secure PTP PMD-slot clear through the existing
  M-mode-mediated update path instead of a raw S-mode store.

The task also proved that the upstream LTP `20260529` route can be acquired,
built, normalized, and executed through true-NaCC Docker in per-case form, with
VM/QEMU/guest/runner artifacts preserved well enough for follow-up analysis.

## Coverage Accounting

Do not convert the task into a broad LTP pass-rate claim.

Useful zero-failure per-case evidence is limited to the named prefix recorded
in the task packet, including early entries through `access03`, selected
`add_key*`, `adjtimex03`, selected `alarm*`, and `bind01`/`bind03`/`bind04`/
`bind05`.

The following are current-route exclusions, not passes:

- environment/config/capability cases such as `access04`, `acct01`, `acct02`,
  `add_key05`, `adjtimex01`, `adjtimex02`, `arch_prctl01`, `bind02`, and
  `bind06`;
- BPF setup cases through `bpf_prog04`, which repeatedly hit
  `RLIMIT_MEMLOCK` / `EPERM` before meaningful BPF assertions.

`bpf_prog05` has preserved raw artifacts and appears to share the same
`RLIMIT_MEMLOCK` / `EPERM` shape, but it did not receive a separate full
log-analyzer section before closeout. It should not be counted as analyzed
coverage.

Entries after `bpf_prog05` in the selected chunk were container-preflighted
only; they were not covered by per-case LTP execution.

## Main Lesson

LOG-enabled NaCC-first full-LTP is the wrong default discovery loop.

It is useful when a specific case has already been selected and rich fault
evidence is needed. It is not efficient for broad case discovery because:

- debug logging makes each case expensive;
- many LTP failures are Docker/container/kernel-config/capability policy
  boundaries rather than NaCC source bugs;
- repeated environment exclusions consume large amounts of wall-clock time;
- broad logs increase task-packet context pressure and slow agent reasoning.

## Recommended Follow-On Route

Start a new task instead of reopening the closed marathon packet.

The next LTP route should be baseline-first:

1. Run Native Docker or another cheap baseline first and build a pass-list of
   cases that are actually viable under the non-NaCC container environment.
2. Classify native/container/environment failures before testing NaCC, so NaCC
   is not blamed for cases that do not run cleanly in the baseline.
3. Run quiet/non-LOG NaCC against the viable pass-list.
4. Compare quiet NaCC with the baseline and identify deltas.
5. Re-run only the interesting deltas or kernel/NaCC-looking failures under
   LOG/debug mode.

This preserves the useful Harness Engineering principle: use expensive,
high-fidelity evidence only after a cheaper gate has isolated a meaningful
case.

## Harness Notes

For future long-running LTP or benchmark tasks:

- Keep raw logs out of task packets when possible; store paths and compressed
  conclusions instead.
- Treat environment exclusions explicitly as exclusions, not passes.
- Avoid asking log analyzer to classify every repeated policy boundary if the
  pattern is already established and the human has chosen to close out.
- When a human stops a marathon run, set the packet to `done/human`, clear
  stale role-pane metadata, and archive the packet/report after recording the
  closeout.

## Primary Artifacts

Active packet before archive:

```text
docs/workflow/tasks/active/TASK_20260620_222557_ltp_fix.md
```

Expected completed packet after archive:

```text
docs/workflow/tasks/completed/TASK_20260620_222557_ltp_fix.md
```

Latest `bpf_prog05` primary guest artifact:

```text
logs/test_runner/TASK_20260620_222557_ltp_fix/guest_artifacts/TASK_20260620_222557_ltp_fix_20260621_230518_upstream_ltp_20260529_chunk16_from_bpf_prog05/TASK_20260620_222557_ltp_fix_20260621_230518_upstream_ltp_20260529_chunk16_from_bpf_prog05/guest_command.log
```

Latest strict marker scan:

```text
logs/test_runner/TASK_20260620_222557_ltp_fix/retry_noapt_hostassist/chunk16_from_bpf_prog05_20260621_230602_host_fault_scan_strict.txt
```
