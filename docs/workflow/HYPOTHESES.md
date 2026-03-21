# Hypotheses

只保留当前仍值得验证的假设；已否定项也要留下反证。

| Hypothesis | Supporting Evidence | Contradicting Evidence | Confidence | Next Validation |
| --- | --- | --- | --- | --- |
| simple fork smoke 已经通过，但更高层容器语义仍可能触发旧的 accounting / reclaim 问题 | 用户于 2026-03-22 口头报告 `cat /etc/hostname; echo done` 可通过；这说明 fork 主线至少跨过了最低门槛 | 尚未补日志路径与 checkpoint，也尚未做 shared memory / `mmap` / 循环压力验证 | medium | 执行 Tier 0 到 Tier 2，观察是否在 shared memory / `mmap` 或循环压力下重新触发旧问题 |
| 容器场景下的 shared memory / `mmap` 可能是下一阶段最容易暴露缺口的地方 | 论文动机本身包含多进程共享内存；动态链接、文件映射、`MAP_SHARED` 都依赖这条语义 | 目前还没有新负面证据证明这些场景一定会失败 | medium | 优先执行 `PLAN_20260322_container_validation.md` 中的 Tier 2 命令 |
| 先前的 `rss` / `rmap` / `pgtables_bytes` 风险可能仍然存在，只是暂时没有在当前最小 smoke 中复现 | 2026-03-17 的日志曾明确出现 `Bad rss-counter state` 与 `non-zero pgtables_bytes`；当前只多了一个更轻量的正向 smoke | 如果 Tier 0 到 Tier 2 持续稳定通过，这个假设会快速降级 | medium | 若新测试复发，再回退到 `TICKET_20260317_fork_accounting_observability.md` 做定向观测 |
