# Debug Patterns

记录反复出现、值得复用的调试模式和失误模式。

维护规则：
- log analyzer 和 coder 可以提交候选 pattern。
- planner 负责判断哪些 pattern 值得留下。
- 已经稳定的高代价反例，优先同步到 `docs/agent/BITTER_LESSONS.md`

## Entry Template

### Pattern: <name>

- Symptom:
- Usual Meaning:
- First Checks:
- Common Misread:
- Evidence Links:

## Current Patterns

### Pattern: 先钉死本轮唯一有效日志

- Symptom: 多轮日志相似，容易沿用上一轮结论
- Usual Meaning: 判断链可能已经偏离当前真实故障
- First Checks:
  - 精确文件名
  - 时间戳
  - 是否是本轮最新实验
- Common Misread: 把“最近看过的日志”当成“当前唯一有效日志”
- Evidence Links:
  - `docs/agent/BITTER_LESSONS.md`

### Pattern: 释放阶段爆炸不等于释放路径是首因

- Symptom: `free_pgtables` / `pagetable_*_dtor` / `kmem_cache_free` 附近崩溃
- Usual Meaning: 更早的初始化、注册或元数据语义可能不完整
- First Checks:
  - ctor 之后对象状态是否成立
  - dtor 之前对象状态是否已损坏
  - `ptp_list` 编码和 level 是否正确
- Common Misread: 直接把最后崩溃点当成真正 root cause
- Evidence Links:
  - `docs/agent/FORK_DEBUG_20260315.md`
  - `record/20260315.md`
