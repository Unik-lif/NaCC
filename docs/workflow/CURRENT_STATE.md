# Current State

最后更新：2026-03-18

## 当前目标

确认 fork+exec 主线里 child fork 映射的 Linux accounting 是否闭环，重点验证：
- `pgtables_bytes` / `mm_inc_nr_ptes` / `mm_inc_nr_pmds`
- leaf PTE 对应的 `rss`
- leaf PTE 对应的 `rmap` / `refcount`
- `ptp_list` 注册后的页表页计数与 teardown 减账是否匹配

## 当前分支 / 检查点

- 主仓：`main`
- `linux/`：`main`
- `opensbi/`：`NoPIC`
- 稳定入口文档：`docs/agent/SESSION_BOOTSTRAP.md`

## 最新已知状态

- `VM_NACC` / agent aperture 误继承不是当前首要矛盾，相关 filter 路径已明显收敛。
- child 的 `ptp_list` 8 个页表页已经能正常注册，`before ctor` 时 `ptdesc->ptl` 为 0，没有再触发此前的 `ptlock_init()` 类问题。
- 当前首个明确异常点已后移到 child `exit_mmap` / reclaim 之后的 mm 记账损坏，而不是 `ptdesc->ptl` 初始化。
- `-32768` 的 `pgtables_bytes` 残值正好对应 8 个 4 KiB PTP 页，强烈指向 fork 注册了 PTP 页，但没有补齐 Linux 侧页表页计数闭环。
- `MM_FILEPAGES` / `MM_ANONPAGES` 负值与 child 中大量 OpenSBI 直接复制的 leaf PTE 相吻合，强烈指向 fork 时缺少等价于标准 `copy_page_range()` 的 leaf accounting。
- 当前已接受的长期方向是 Linux-friendly fork：Linux 尽量回到原生 fork 主线，只在 secure 页表写入点依赖 OpenSBI，而不是继续把当前原型里的局部旁路实现或 `semantic replay` 当最终模型。
- `docs/workflow/` 已建立，后续新会话应以这里为当前状态入口，再回读 `docs/agent/` 的稳定知识。
- 主仓工作树当前不是干净状态；但 `linux/` 与 `opensbi/` 当前 `git status --short` 可视为干净，后续实验仍应显式记录 checkpoint。

## 阻塞项

- 最新实验的准确测试命令、源码 checkpoint 和结果摘要还没有补录到统一状态面。
- 尚未确认 child `pgtables_bytes` 漏账发生在 `ptp_list` 注册阶段，还是发生在后续 reclaim / free 路径的计数不对称。
- 尚未确认 OpenSBI 复制出来的 child leaf PTE 在 Linux 侧缺失了哪些具体建账动作：`rss`、`rmap`、`folio/page refcount`，或其中组合。

## 最新证据

- `logs/fork_exec_default_freshwait_20260317_qemu_20260317_151037.log`
  - child `ptp_list` entries=8，注册阶段通过，`before ctor` 的 `ptl` 为 0。
  - child 页表树里已看到大量 leaf PTE，日志统计 `Total user leaf pages: 403`。
  - child `exit_mmap` 在 pid=770 上启动，176.31s 左右 Linux / OpenSBI 各自回收了 8 个 fork 出来的 PTP 页。
  - 176.385s 出现首个明确异常点：`Bad rss-counter state` 与 `non-zero pgtables_bytes on freeing mm: -32768`。
- `docs/agent/FORK_DEBUG_20260315.md`
  - 旧结论中关于 child secure PTP 生命周期不完整的判断，现应降级为次级问题或历史背景。

## 本次更新后应优先补充

- 当前正在测试的准确场景命令。
- 最新实验对应的源码 checkpoint 或 commit id。
- 针对 `pgtables_bytes` / `rss` / `rmap` / `refcount` 的实现 ticket，而不只是日志路径。
