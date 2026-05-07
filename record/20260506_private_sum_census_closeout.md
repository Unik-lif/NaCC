# PRIVATE_DATA SUM Census Closeout

- Task: `TASK_20260506_163109_sum_coverage`
- Date: 2026-05-06
- Verdict: accepted T1 instrumentation evidence.

## Scope

This slice added OpenSBI-side aggregate trap-time SUM reporting for confirmed NaCC PRIVATE_DATA load/store-style mediation. It did not expand Linux wrappers, string wrappers, transaction mechanisms, staging, page unseal behavior, PRIVATE_DATA enforcement, `fallback_scalar_usercopy`, or per-trap logging.

## Build And Runtime Evidence

- `make opensbi` completed successfully.
- `printf` workload artifact: `logs/TASK_20260506_163109_sum_coverage_printf_retry_recovered_qemu_20260506_172621.log`; VM companion `logs/TASK_20260506_163109_sum_coverage_printf_retry_recovered_vm_20260506_172621.log`.
- Repaired `cat` workload artifact: `logs/TASK_20260506_163109_sum_coverage_cat_retry_harnessfix_01_20260506_173956_qemu_20260506_174358.log`; VM companion `logs/TASK_20260506_163109_sum_coverage_cat_retry_harnessfix_01_20260506_173956_vm_20260506_174358.log`.
- Both workloads reached `[NaCC] Auto-running:` and exited with `[NaCC][ssh-auto-exit] code=0`.
- Existing TX census lines remained present, all five API census rows were present, and scalar per-event TX begin/end printk remained suppressed.

## Census Lines

`printf alpha >/dev/null; echo kernel_read_done`:

```text
[NACC][private-sum-census-total] private_data_load=6445 private_data_store=1697 private_data_total=8142 sum_on=1996 sum_off=6146 tx_on_sum_on=839 tx_on_sum_off=0 tx_off_sum_on=1157 tx_off_sum_off=6146 sum_source=saved_regs_mstatus tx_active_predicate=current_task_valid_api count_mode=exact
[NACC][uaccess-tx-census-total] private_data_load=6445 private_data_store=1697 private_data_total=8142 tx_begin_total=334 tx_end_total=334 tx_active_covered_private_traps=839 uncovered_private_traps=7303 scalar_event_printing=census_mode_suppressed
```

`cat /etc/hostname; echo done` after harness timeout propagation repair:

```text
[NACC][private-sum-census-total] private_data_load=18345 private_data_store=5169 private_data_total=23514 sum_on=4127 sum_off=19387 tx_on_sum_on=1792 tx_on_sum_off=1781 tx_off_sum_on=2335 tx_off_sum_off=17606 sum_source=saved_regs_mstatus tx_active_predicate=current_task_valid_api count_mode=exact
[NACC][uaccess-tx-census-total] private_data_load=18345 private_data_store=5169 private_data_total=23514 tx_begin_total=551 tx_end_total=551 tx_active_covered_private_traps=3573 uncovered_private_traps=19941 scalar_event_printing=census_mode_suppressed
```

## Arithmetic Checks

- `printf`: `6445 + 1697 == 8142`; `1996 + 6146 == 8142`; `839 + 0 + 1157 + 6146 == 8142`; `839 + 7303 == 8142`; `334 == 334`.
- `cat`: `18345 + 5169 == 23514`; `4127 + 19387 == 23514`; `1792 + 1781 + 2335 + 17606 == 23514`; `3573 + 19941 == 23514`; `551 == 551`.

## Interpretation

The aggregate answer is that uncovered PRIVATE_DATA traps in both bounded workloads are mainly `SUM=0`, not `SUM=1`:

- `printf`: `tx_off_sum_off=6146` vs `tx_off_sum_on=1157`.
- `cat`: `tx_off_sum_off=17606` vs `tx_off_sum_on=2335`.

This does not identify Linux call sites and does not prove the root cause of uncovered traps. It also does not justify wrapper expansion by itself.

The repaired `cat` run has a suspicious nonzero `tx_on_sum_off=1781` bucket. That should be treated as a separate semantic investigation candidate, not as a direct SUM-census implementation failure from this packet.

## Evidence Boundary

Observed facts are the preserved VM execution markers, final QEMU census lines, arithmetic identities, and absence of scalar per-event TX begin/end lines. Inference begins when interpreting `SUM=0` / `SUM=1` bucket distributions under the saved-`regs->mstatus` SUM sample and current-task TX-active predicate.
