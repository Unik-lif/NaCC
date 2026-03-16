# Next Steps

按优先级排序。完成或证伪后及时更新状态。

| Priority | Action | Owner | Status | Dependency |
| --- | --- | --- | --- | --- |
| P0 | 用 `LOG_ANALYSIS_TEMPLATE.md` 重新分析 `logs/nacc_qemu_20260316_221143.log`，确认首个异常点和前置事件 | log analyzer | pending | 最新日志路径 |
| P0 | 把本轮实验的准确测试命令、目标和结论补进 `CURRENT_STATE.md` 与 `EXPERIMENT_LOG.md` | human | pending | 最近一次手动实验信息 |
| P1 | 若日志仍指向 child PTP 生命周期问题，产出一张只包含观测点增强的 implementation ticket | planner | pending | 最新日志分析结果 |
| P1 | 在 Linux / OpenSBI 的 `ptp_list` 与 pagetable ctor/dtor 两端补最小日志或断言 | coder | pending | 已批准的 implementation ticket |
| P2 | 将已反复验证的 fork+exec 结论从临时记录同步回 `docs/agent/NACC_KNOWLEDGE_BASE.md` | planner | pending | 结论稳定 |
