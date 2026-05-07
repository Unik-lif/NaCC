# Primary Uaccess TX PRIVATE_DATA Trap Census Closeout

Date: 2026-05-06
Task: `TASK_20260506_013254_count`

## Summary

This task produced a statistics-only census for the five already-standardized
uaccess TX wrappers:

- `copy_from_user`
- `copy_to_user`
- `get_user`
- `put_user`
- `clear_user`

The final target was not length or address distribution. The key question was:
how many `PRIVATE_DATA` traps occur while each of these five TX API kinds is
active?

The implemented route added an opt-in diagnostic mode:

```text
nacc.uaccess_tx_report=census
```

In census mode, scalar wrappers such as `get_user` and `put_user` are counted
without printing every per-event TX begin/end line. Linux sends count-only
TX-active begin/end context to OpenSBI, and OpenSBI attributes `PRIVATE_DATA`
load/store traps to the currently active TX API kind. This is API-active
coverage, not individual trap-to-transaction attribution.

## Validation

Required workloads were run with:

```text
nacc.uaccess_tx_report=census
```

Both required workloads passed:

- `printf alpha >/dev/null; echo kernel_read_done`
- `cat /etc/hostname; echo done`

The optional `wc -c /etc/hostname; echo done` workload was not run.

Primary artifacts:

- `logs/TASK_20260506_013254_count_printf_01_20260506_021900_qemu_20260506_022252.log`
- `logs/TASK_20260506_013254_count_printf_01_20260506_021900_vm_20260506_022252.log`
- `logs/TASK_20260506_013254_count_cat_01_20260506_022258_qemu_20260506_022701.log`
- `logs/TASK_20260506_013254_count_cat_01_20260506_022258_vm_20260506_022701.log`

Builds completed before the runs:

- `make opensbi`
- `make linux-update`

## Census Results

### Workload 1: `printf alpha >/dev/null; echo kernel_read_done`

Final total census:

```text
private_data_load=5442
private_data_store=1802
private_data_total=7244
tx_begin_total=376
tx_end_total=376
tx_active_covered_private_traps=881
uncovered_private_traps=6363
```

Per API:

| API | tx_begin | tx_end | PRIVATE_DATA load | PRIVATE_DATA store | PRIVATE_DATA total |
| --- | ---: | ---: | ---: | ---: | ---: |
| `copy_from_user` | 3 | 3 | 72 | 0 | 72 |
| `copy_to_user` | 11 | 11 | 0 | 242 | 242 |
| `get_user` | 177 | 177 | 177 | 0 | 177 |
| `put_user` | 183 | 183 | 0 | 183 | 183 |
| `clear_user` | 2 | 2 | 0 | 207 | 207 |

All final per-API rows reported `tx_open_delta=0`.

### Workload 2: `cat /etc/hostname; echo done`

Final total census:

```text
private_data_load=18363
private_data_store=13445
private_data_total=31808
tx_begin_total=579
tx_end_total=579
tx_active_covered_private_traps=3601
uncovered_private_traps=28207
```

Per API:

| API | tx_begin | tx_end | PRIVATE_DATA load | PRIVATE_DATA store | PRIVATE_DATA total |
| --- | ---: | ---: | ---: | ---: | ---: |
| `copy_from_user` | 15 | 15 | 275 | 131 | 406 |
| `copy_to_user` | 19 | 19 | 0 | 450 | 450 |
| `get_user` | 272 | 272 | 272 | 0 | 272 |
| `put_user` | 268 | 268 | 540 | 485 | 1025 |
| `clear_user` | 5 | 5 | 0 | 1448 | 1448 |

All final per-API rows reported `tx_open_delta=0`.

## Interpretation

The census mode satisfied the task goal:

- All five primary wrappers were counted.
- Begin/end counts were paired in the final dumps for both required workloads.
- Scalar wrappers were counted without per-event TX log flooding.
- Both required workloads exited successfully.
- No crash signatures were found in the required QEMU logs.

The large uncovered `PRIVATE_DATA` trap totals are expected under this census
shape. They mean those traps were not observed inside one of the five active
wrapper windows under the accepted shallow TX-active model. They should not be
interpreted as full trap provenance, because this task deliberately did not
implement trap-to-transaction association.

## Boundaries

This task did not:

- instrument `strncpy_from_user`
- instrument `strnlen_user`
- add new uaccess wrappers
- change `PRIVATE_DATA` enforcement
- unseal ordinary user pages
- implement staging
- patch `fallback_scalar_usercopy`
- associate individual traps with individual transaction IDs

The result is a compact API-active coverage census, suitable as evidence for
the current five-wrapper statistics question.
