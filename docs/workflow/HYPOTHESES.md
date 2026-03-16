# Hypotheses

只保留当前仍值得验证的假设；已否定项也要留下反证。

| Hypothesis | Supporting Evidence | Contradicting Evidence | Confidence | Next Validation |
| --- | --- | --- | --- | --- |
| child 新 PTP 没有达到 Linux pagetable allocator 等价完成态 | `docs/agent/FORK_DEBUG_20260315.md` 指向 teardown 在 `pagetable_*_dtor` / `kmem_cache_free` 附近暴露问题 | 还没有直接证据证明 ctor 后状态立即异常 | medium | 在 `nacc_register_fork_ptp_list()` 与 dtor 前后观测 `ptdesc` / `ptdesc->ptl` |
| 问题不是 `VM_NACC` 误继承，而是后续页表页生命周期闭环缺失 | 3 月 15 日文档说明 Linux / OpenSBI 两侧 filter 已明显生效 | 仍需用 3 月 16 日最新日志确认没有新回归 | medium | 重新分析 `logs/nacc_qemu_20260316_221143.log` 的首个异常点 |
| child PTP 可能是“初始化后被破坏”，而不是“从未初始化” | 当前只看到释放阶段暴露异常，还未在注册完成点做强观测 | 没有证据证明 ctor 后状态曾经正常 | low | 补两端日志，比较注册后与释放前对象状态 |
