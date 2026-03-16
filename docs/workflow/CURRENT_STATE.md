# Current State

最后更新：2026-03-17

## 当前目标

确认 fork+exec 主线里 child 新页表页的 Linux 生命周期是否闭环，重点验证：
- `ptp_list`
- `pagetable_*_ctor`
- `ptdesc->ptl`
- `pagetable_*_dtor`

## 当前分支 / 检查点

- 主仓：`main`
- `linux/`：`main`
- `opensbi/`：`NoPIC`
- 稳定入口文档：`docs/agent/SESSION_BOOTSTRAP.md`

## 最新已知状态

- `VM_NACC` / agent aperture 误继承不是当前首要矛盾，相关 filter 路径已明显收敛。
- 当前最强问题主线已后移到 child 新 PTP 的 ctor / ptlock / dtor 语义是否完整。
- `docs/workflow/` 已建立，后续新会话应以这里为当前状态入口，再回读 `docs/agent/` 的稳定知识。
- 工作树当前不是干净状态；主仓有未提交变更，`opensbi/` 子仓也处于修改态，后续实验应显式记录基线。

## 阻塞项

- 最新实验的准确测试命令、源码 checkpoint 和结果摘要还没有补录到统一状态面。
- `logs/nacc_qemu_20260316_221143.log` 还没有按统一模板重新复盘。
- 尚未确认 child PTP 是“从未被正确初始化”还是“初始化后在后续路径被破坏”。

## 最新证据

- `docs/agent/FORK_DEBUG_20260315.md`
  - 当前最强假设是 child secure PTP 未达到 Linux pagetable allocator 等价完成态。
- `record/20260315.md`
  - 当日结论同样指向 `ptp_list -> ctor -> dtor` 闭环验证。
- `logs/nacc_qemu_20260316_221143.log`
  - 这是当前仓库里最新一份 QEMU 日志，应作为下一轮日志分析起点。
- `logs/nacc_vm_20260316_221143.log`
  - 对应同批次 VM 侧日志。

## 本次更新后应优先补充

- 当前正在测试的准确场景命令。
- 最新实验对应的源码 checkpoint 或 commit id。
- 最新日志的结论摘要，而不只是路径。
