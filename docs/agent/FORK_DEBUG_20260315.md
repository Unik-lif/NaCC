# NaCC fork+exec 调试资产（截至 2026-03-15）

> 目的：沉淀这轮 `fork+exec` 调试中已经明显收敛的主线判断，避免后续又把重点拉回 `VM_NACC` 误继承。

## 1. 当前状态结论

### 1.1 `VM_NACC` / agent aperture 误继承已明显缓解

从 `logs/nacc_qemu_20260314_225326.log` 可直接看到：

- Linux 在 `dup_mmap()` 中已丢弃 child 继承的 `VM_NACC` VMA
- Linux 侧 `filter_ranges=1`
- OpenSBI 侧 `filter nr_ranges=1`

因此，上一轮那种最早出现的：

- `Bad page map @ 3ec0000000`
- `Bad page state pfn:180000 ~ 180009`

这轮已经不再是首个主故障。

### 1.2 当前新的主线问题

当前更像是：

- OpenSBI fork 时为 child 分配了新的 secure PTP
- Linux 通过 `ptp_list` 事后补注册
- 但这些 child PTP **没有完整具备 Linux pagetable allocator 的初始化结果**

最新日志中的首个致命点已经后移到：

- `exit_mmap -> free_pgd_range -> free_pgtables -> kmem_cache_free`

这更像是 teardown 阶段在释放一个“语义不完整”的 pagetable object。

## 2. 当前最强 root cause 假设

不是简单的“secure page 被当普通页 free”，而更像是：

- child PTP 对应的 `struct page` / `ptdesc` 语义不完整
- `pagetable_pmd_ctor()` / `pagetable_pte_ctor()` 没有真正补齐到位
- `ptlock_init()` 的结果不成立
- 在 split ptlock 配置下，`ptdesc->ptl` 为 NULL、脏值，或后续被错误破坏

于是到 free 路径：

- `pagetable_*_dtor()`
- `ptlock_free()`
- `kmem_cache_free(page_ptl_cachep, ptdesc->ptl)`

这里才最终炸出来。

## 3. 当前最值得验证的点

### 3.1 `ptp_list` 本身是否正确

需要确认：

- OpenSBI 回传的每个 `new_pfn + level` 是否完整
- `level == 1` 是否稳定对应 child PMD page
- `level == 0` 是否稳定对应 child PTE page

若 level 编码错位，Linux 侧 ctor 会直接错配。

### 3.2 Linux 侧是否真的完成了 ctor

在 `linux/arch/riscv/mm/nacc.c:nacc_register_fork_ptp_list()` 里，应当对每个 child PTP 观察：

- ctor 前的 `ptdesc` 状态
- ctor 后的 `ptdesc` 状态
- `ptdesc->ptl` 是否从空变成有效对象

重点不是“函数是否返回 true”，而是：

- ctor 后状态是否真的等价于 Linux 原生 `pmd_alloc/pte_alloc` 完成态

### 3.3 区分“从未初始化”与“后续损坏”

需要至少两个观测点：

1. `nacc_register_fork_ptp_list()` 刚完成之后
2. `pagetable_*_dtor()` / `__pte_free_tlb()` / `__pmd_free_tlb()` 进入之前

判断方式：

- 若刚注册完 `ptdesc->ptl` 就不对，更像“从未初始化”或 ctor 前提不成立
- 若注册后正常、释放前才坏，更像“提前析构 / 二次析构 / 中途破坏”

## 4. 对当前设计的判断

当前设计仍可继续推进，但有明确前提：

- OpenSBI 返回 `ptp_list`
- Linux 必须对每个 child PTP 补齐 **完整的 pagetable ctor/ptlock 语义**

这里不要求字面上调用 `pmd_alloc/pte_alloc`，但要求满足同等 postcondition：

- 合法 `struct page / ptdesc`
- 正确 ctor
- 有效 `ptdesc->ptl`
- 后续 dtor 可对称执行

如果这些前提不成立，就不能只停留在“ptp_list + ctor 调用”这一层，而要补一层更完整的 child PTP 注册/初始化语义。

## 5. 下一步行动顺序

1. 在 OpenSBI `ptp_list push` 与 Linux `nacc_register_fork_ptp_list()` 两侧补逐项日志。
2. 对每张 child PTP 记录：
   - `new_pfn`
   - `level`
   - ctor 前后 `ptdesc`
   - ctor 前后 `ptdesc->ptl`
3. 在 `pagetable_pmd_dtor()` / `pagetable_pte_dtor()` 之前补日志，确认释放前对象是否已损坏。
4. 先把 child PTP ctor/ptlock 闭环查清，再决定是否需要调整 fork PTP 注册策略。

## 6. 一句话总结

这轮 fork+exec 调试的主线已经从：

- “`VM_NACC` / agent aperture 误继承”

后移到：

- “child 新 PTP 是否真正具备 Linux pagetable allocator 等价初始化语义”

`kmem_cache_free()` 只是最后炸出来的位置，真正应优先验证的是：

- `ptp_list -> ctor -> ptlock -> dtor`

这一整段是否闭环。
