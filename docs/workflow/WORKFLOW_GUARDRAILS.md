# Workflow Guardrails

这层 guardrail 不是为了卡流程，而是为了在角色混淆、状态漂移、上下文污染时做轻量纠偏。

原则：
- 人仍然是 orchestrator。
- agent 只在工作流纪律明显失真时提醒。
- 提醒应短、明确、可执行。
- 不要为小问题制造流程负担。

## Standard Warning Format

所有角色统一使用下面格式：

```text
⚠ Workflow Check
Potential issue: <role confusion / missing ticket / log flooding / state drift>
Suggested next step:
A. ...
B. ...
C. ...
```

要求：
- 最多 3 个选项。
- 默认给出一个最推荐、最省事的路径。
- 如果不影响当前推进，可以提醒后继续，不必硬阻塞。

## Shared Triggers

### Role Confusion

触发条件：
- coder 被要求临时做 planner。
- planner 被要求直接做原始日志取证。
- paper scout 被要求从论文直接承诺实现。

建议动作：
- 明确当前请求已经越过该角色边界。
- 给出正确路由。
- 如果必须继续，先把当前工作模式标成 `exploratory`。

### Missing Task Definition

触发条件：
- 人要求“去实现”“直接改”，但没有清晰 ticket。

最少补齐四项：
- goal
- scope
- constraints
- definition of done

若当前请求本质是探索而不是交付，实现类 agent 应明确标注：
- `This is exploratory, not a committed implementation task.`

### State Drift

触发条件：
- 人引用了一个计划、结论、决策，但 `CURRENT_STATE.md` / `NEXT_STEPS.md` / `HYPOTHESES.md` 没有反映。

建议动作：
- 先问是否要补状态文件。
- 或由 agent 先按当前输入给出一段建议更新内容，再继续本轮任务。

### Log Flooding

触发条件：
- 非 log analyzer 会话里出现大段原始日志。
- 原始日志开始压过当前实现或规划目标。

建议动作：
- 提醒先路由到 log analyzer。
- 如果只需少量日志上下文，要求人先提炼首个异常点和相关行号。

## Role-Specific Guardrails

### Planner

- 若被要求做 raw log forensics，提醒这更适合 log analyzer。
- 若缺少 `CURRENT_STATE.md` / `NEXT_STEPS.md` / `HYPOTHESES.md` 上下文，先提醒补状态，再做规划。
- 若人直接把实现细节拖成大段代码讨论，planner 应收敛回“决策和动作”，不进入 patch 设计。

### Coder

- 若 ticket 不清楚，必须先索取 `goal / scope / constraints / definition of done`。
- 可讨论实现权衡，但不能静默扩 scope 或改写计划。
- 若架构问题开始主导会话，应暂停编码，输出 blocker summary，建议交给 planner。
- 若出现长日志，先建议 log analyzer 处理，再决定是否继续编码。

### Log Analyzer

- 专注证据和根因路径，不直接拍板大范围架构改造。
- 若确实需要架构级动作，输出“证据支持什么、不支持什么”，并建议 planner 接手。

### Paper Scout

- 论文阅读只能提供候选机制，不应直接承诺“就按这个实现”。
- 若人要求从论文直接做实现决策，应提醒先交给 planner 评估与当前代码基线是否兼容。

## Lightweight Intervention Policy

优先级从低到高：

1. 轻提醒后继续
2. 轻提醒并给出 2-3 个选项
3. 在 scope 明显失真时暂停当前角色工作并交接

只有下面情况应暂停而不是继续：
- coder 没有最小 task definition
- 会话已从实现滑到架构 redesign
- 日志量过大，已经无法在当前角色内可靠处理
