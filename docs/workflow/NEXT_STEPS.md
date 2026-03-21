# Next Steps

按优先级排序。完成或证伪后及时更新状态。

| Priority | Action | Owner | Status | Dependency |
| --- | --- | --- | --- | --- |
| P0 | 把 2026-03-22 simple fork smoke 的准确测试命令、源码 checkpoint、日志结论补进 `CURRENT_STATE.md` 与 `EXPERIMENT_LOG.md` | human | pending | 最近一次手动实验信息 |
| P0 | 将 fork 长期方向固定为 Linux-friendly fork，并要求后续 coder 按“Linux 原生路径 + OpenSBI 写辅助”方向收敛实现 | planner | completed | `PLAN_20260318_linux_friendly_fork.md` |
| P0 | 产出一张只覆盖 accounting 观测点的 implementation ticket：页表页计数与 leaf 建账分开看 | planner | completed | 最新日志分析结果 |
| P0 | 产出一张容器语义验证计划，明确共享内存 / `mmap` 是第一层级测试项，并给出具体命令 | planner | completed | `PLAN_20260322_container_validation.md` |
| P1 | 先执行 Tier 0 到 Tier 2，尤其是 shared memory / `mmap` 相关命令，用来判断容器语义是否已基本成立 | human / test runner | pending | `PLAN_20260322_container_validation.md` |
| P1 | Tier 0 到 Tier 2 若稳定通过，再推进 Tier 3 小而真实的应用，暂不直接以完整 Ubuntu 镜像为近期目标 | planner / human | pending | `PLAN_20260322_container_validation.md` |
| P2 | 如果 shared memory / `mmap` 或循环压力下重新暴露旧问题，再启用 accounting 观测 ticket，检查 `pgtables_bytes`、`rss`、`rmap`、`refcount` | planner / coder | pending | `TICKET_20260317_fork_accounting_observability.md` |
| P2 | 在 Stage 1/2 结束后，决定 Linux-friendly fork 的具体接回形式：直接恢复更多原生子路径 / 仅将 secure write 点委托给 OpenSBI / 极少数点保留临时旁路 | planner | pending | 观测结果 |
| P3 | 将 `bitmap` 防护作为后续 security hardening 项纳入长期计划，但排在 fork / `mmap` / shared memory 语义稳定之后 | planner / coder | pending | `PLAN_20260318_linux_friendly_fork.md` |
| P3 | 将已稳定的 smoke / shared memory / `mmap` 结论同步回 `docs/agent/NACC_KNOWLEDGE_BASE.md` | planner | pending | 结论稳定 |
