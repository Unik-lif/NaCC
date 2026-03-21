# Implementation Ticket

## Goal

- 确认 NaCC fork+exec 当前失败是否由 child mm accounting 缺口导致，并将问题拆分为两层：
- 页表页计数缺口：`pgtables_bytes` / `mm_inc_nr_ptes` / `mm_inc_nr_pmds`
- leaf 页建账缺口：`rss` / `rmap` / `folio/page refcount`

## Scope

- 在 `nacc_register_fork_ptp_list()` / `page_nacc_register_ptp()` 一侧补最小观测，记录 child mm 的页表页计数是否随 PTP 注册同步增加。
- 在 `exit_mmap()` / `zap_pte_range()` 一侧补最小观测，确认 teardown 正在减哪些账。
- 以聚合计数或关键样本为主，不做 403 个 leaf 页的逐页海量打印。
- 输出一份足以回答“缺的是页表账、leaf 账，还是两者都有”的日志证据。

## Non-Goals

- 这张 ticket 不直接修复 fork accounting。
- 不重做 OpenSBI fork 方案，不切回 Linux 全量 `copy_page_range()`。
- 不重新把主问题拉回 `VM_NACC` 误继承或 `ptdesc->ptl` 初始化。

## Constraints

- 观测点必须分层：先看页表页计数，再看 leaf 页建账，避免日志混在一起无法归因。
- 除诊断日志/断言外，不改变当前 fork 行为。
- 保持日志可读，优先打印 child pid、mm、页数、计数 delta 和少量样本页。
- 继续遵守当前状态机边界：`thread.nacc_flag` 负责流程身份，`mm->context.nacc_state` 负责 reclaim 语义。

## Files Likely Involved

- `linux/arch/riscv/mm/nacc.c`
- `linux/arch/riscv/kernel/sys_riscv.c`
- `linux/mm/memory.c`
- `linux/mm/mmap.c`
- `linux/kernel/fork.c`

## Definition Of Done

- 能在一轮 fork+exec 日志里明确看到 child `ptp_list` 注册前后 `mm_pgtables_bytes(mm)` 的变化。
- 能明确判断 8 个 PTP 页是否都完成了对应的页表页记账。
- 能明确判断 child leaf teardown 时，`rss` / `rmap` / `refcount` 是在减已经建过的账，还是在减从未建立过的账。
- 日志结论足够让 planner 在下轮选择修复路径：
- A. 只补页表页计数
- B. 只补 leaf accounting
- C. 两者都补

## Validation Plan

- `make linux-update`
- 用当前同一 fork+exec 场景重跑一轮
- 检查新日志中：
- `nacc_register_fork_ptp_list()` 的注册计数与 `mm_pgtables_bytes(mm)` delta
- `exit_mmap()` / `zap_pte_range()` 前后的 mm counter 变化
- 首个异常点是否仍然是 `Bad rss-counter state` / `non-zero pgtables_bytes`

## Rollback Notes

- 若日志过大或结论已经稳定，移除这些临时观测点，仅保留必要的长期 guardrail/assert。
