# SQLite Existing-Docker Smoke Result

Date: 2026-06-11

Task: `TASK_20260611_161031_sqlite`

## Outcome

SQLite was proven to run a lightweight workload in both existing Docker arms:

- native arm: container `nacc_ae_native`, runtime `runc-origin`
- NaCC arm: container `nacc_ae_nacc`, runtime `runc`
- SQLite path inside both containers: `/test/sqlite/bin/sqlite3`
- SQLite version: `3.53.2 2026-06-03`
- SQLite binary sha256 in both arms:
  `a2239f87fb0278e71b0e528e999780491593e5303d36cb89ce82494f13ebb034`
- workload SQL sha256:
  `90f096d2eed294fba813686e4683d1e9b30fc638d079a5e7a75afd15d821a743`
- workload return code: `0` in both arms
- workload stdout sha256 in both arms:
  `359acb6708a3947edf601746d395175f8d5012322782f2679bc155221adb28de`

This is acceptable smoke/performance-sanity evidence: SQLite runs through the
existing Docker-based path, and the first rough timing sample does not show an
extreme NaCC-vs-native gap.

## Rough Timing Sample

Timing method:

```text
guest date +%s%N around docker exec; fallback to seconds if %N unsupported
```

Recorded values:

| Metric | Value |
| --- | ---: |
| native real seconds | `3.627455` |
| NaCC real seconds | `3.305148` |
| NaCC / native ratio | `0.911148` |

Interpretation boundary:

- This is a single guest-wrapper timing around `docker exec`.
- It is useful only as an initial smoke sanity check.
- It is not repeatability proof, steady-state timing, statistical evidence, or
  final benchmark-image readiness.
- Do not cite the ratio as a polished SQLite performance claim.

## Artifacts

Completed packet:

```text
docs/workflow/tasks/completed/TASK_20260611_161031_sqlite.md
```

Primary artifact root:

```text
logs/test_runner/TASK_20260611_161031_sqlite/run_20260611_183219_retry/
```

Key preserved files:

```text
logs/test_runner/TASK_20260611_161031_sqlite/run_20260611_183219_retry/extracted_guest_artifact/summary.tsv
logs/test_runner/TASK_20260611_161031_sqlite/run_20260611_183219_retry/extracted_guest_artifact/comparison.tsv
logs/test_runner/TASK_20260611_161031_sqlite/run_20260611_183219_retry/extracted_guest_artifact/return_codes.tsv
logs/test_runner/TASK_20260611_161031_sqlite/run_20260611_183219_retry/extracted_guest_artifact/timing.tsv
logs/test_runner/TASK_20260611_161031_sqlite/run_20260611_183219_retry/timeout_and_harness_context.txt
```

## Harness And Setup Notes

The successful retry did not rebuild Linux, QEMU, OpenSBI, or Agent. The
test-runner preflight recorded those submodule statuses as clean.

The retry bundle first hit a stale QEMU owner for `NaCC.qcow2`. The cleanup
helper removed stale `qemu-system-riscv64` pid `1498934`, then the final retry
completed with `debug_batch_retry.rc=0`.

No support package was installed in the successful retry. The earlier failure
using `/usr/bin/time` was avoided by using the guest `date +%s%N` wrapper.

## Follow-Up Boundary

Future SQLite benchmark work should be a new scoped task if it needs any of:

- repeated runs or stronger statistics,
- improved timing methodology,
- stable installed SQLite support in a reusable benchmark image,
- broader SQLite workloads,
- final benchmark-image commit/save/productization.

Do not reopen this smoke packet for those goals unless the human explicitly
asks to reuse it.
