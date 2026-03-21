# Hypotheses

只保留当前仍值得验证的假设；已否定项也要留下反证。

| Hypothesis | Supporting Evidence | Contradicting Evidence | Confidence | Next Validation |
| --- | --- | --- | --- | --- |
| child fork leaf mappings 缺少 Linux 等价 accounting（`rss` / `rmap` / `refcount`） | 当前 NaCC fork 在 `dup_mmap()` 中跳过 `copy_page_range()`；新日志显示 child 侧有大量 leaf PTE，teardown 后立刻出现 `MM_FILEPAGES` / `MM_ANONPAGES` 负值 | 还没有直接观测到缺的是哪一项建账动作 | high | 对照标准 `copy_present_ptes()` 路径，在 NaCC fork 后补观测 leaf 页的 `rss` / `rmap` / `refcount` 是否曾被建立 |
| `ptp_list` 注册只补了 `pagetable_*_ctor`，但没有补齐 child mm 的页表页计数（`pgtables_bytes`） | `non-zero pgtables_bytes on freeing mm: -32768` 正好等于 8 * 4096，而本次 child `ptp_list` entries=8 | 还未直接证明 `mm_inc_nr_ptes` / `mm_inc_nr_pmds` 在注册阶段完全没走 | high | 在 `nacc_register_fork_ptp_list()` 的 level 分支中观测并比对 `mm_pgtables_bytes(mm)` 与 PTP 注册数变化 |
| child 新 PTP 的 ctor / ptlock 生命周期已基本闭环，不再是当前首因 | 新日志里 8 个 child PTP 都能注册成功，`before ctor` 的 `ptl` 为 0，且没有再出现此前的 `ptlock_init()` BUG | 仍未彻底排除后续 reclaim 时存在次级破坏 | medium | 仅保留最小观测，确认 dtor 前后 `ptdesc->ptl` 稳定；除非出现新反证，否则不再作为主线 |
