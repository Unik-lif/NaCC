# NaCC Workflow Layer

这层文档是给人和多个 agent 共用的轻量协作层。

只做三件事：
- 固定共享状态，减少每次新会话重新建模。
- 固定交接格式，减少“知道很多但落不下来”。
- 固定角色边界，减少 planner / coder / log analyzer / paper scout 职责漂移。

它不替代 `docs/agent/`：
- `docs/agent/` 放长期项目知识、稳定设计结论、关键代码入口。
- `docs/workflow/` 放当前状态、假设、下一步、实验记录、交接模板。

这层现在还承担一个更轻的“项目记忆层”：
- `docs/workflow/` 里的 memory 文件用于帮助未来 revived agent 快速恢复上下文。
- planner 是 durable memory 的主维护者。
- 其他角色提交证据和摘要，由 planner 决定哪些内容升格为长期记忆。

## 快速入口

- 先看当前状态：
  - `CURRENT_STATE.md`
  - `NEXT_STEPS.md`
  - `HYPOTHESES.md`
- 需要长期记忆：
  - `DECISIONS.md`
  - `ARCHITECTURE_NOTES.md`
  - `DEBUG_PATTERNS.md`
  - `IMPLEMENTATION_NOTES.md`
- 需要角色约束：
  - `AGENT_PLANNER.md`
  - `AGENT_CODER.md`
  - `AGENT_LOG_ANALYZER.md`
  - `AGENT_PAPER_SCOUT.md`
  - `AGENT_TEST_RUNNER.md`
- 需要 guardrail：
  - `WORKFLOW_GUARDRAILS.md`
  - `HUMAN_OPERATOR_CHECKLIST.md`

## 文件说明

- 状态面：`CURRENT_STATE.md` / `NEXT_STEPS.md` / `HYPOTHESES.md`
- 记忆面：`DECISIONS.md` / `ARCHITECTURE_NOTES.md` / `DEBUG_PATTERNS.md` / `IMPLEMENTATION_NOTES.md`
- 操作面：`KNOWN_GOOD.md` / `EXPERIMENT_LOG.md`
- 模板面：`*_TEMPLATE.md`
- 角色面：`AGENT_*.md`
- guardrail：`WORKFLOW_GUARDRAILS.md` / `HUMAN_OPERATOR_CHECKLIST.md`

## Agent 如何维护清晰度

- 人仍然是 orchestrator。
- planner 发现缺少当前状态时，应先要求补最小状态。
- coder 发现没有清晰 ticket 时，应先要 `goal / scope / constraints / definition of done`。
- 非 log analyzer 会话里如果出现大段日志，应提醒先做日志分析。
- 如果人引用了未写入状态文件的计划或决定，agent 应询问是否先回写状态。
- 如果实现会话被架构讨论劫持，coder 应暂停扩 scope，转而输出 blocker summary。
- durable memory 由 planner 主维护，其他角色默认只提交候选内容。

统一提醒格式见 [WORKFLOW_GUARDRAILS.md](/home/link/NaCC/docs/workflow/WORKFLOW_GUARDRAILS.md)。

## 推荐迭代循环

1. 更新 `CURRENT_STATE.md`
2. 分析最新日志
3. 修订 `NEXT_STEPS.md` 与 `HYPOTHESES.md`
4. 生成 implementation ticket
5. 进行受控修改
6. 人手动运行实验
7. 把结果记入 `EXPERIMENT_LOG.md`
8. 由 planner 做 5 分钟 memory update：
   - 更新 `DECISIONS.md` / `ARCHITECTURE_NOTES.md` / `DEBUG_PATTERNS.md` / `IMPLEMENTATION_NOTES.md`
   - 只有稳定结论再同步到 `docs/agent/`

## 维护规则

- 先写状态，再开工。
- 已被证伪的路径，必须写进 `HYPOTHESES.md` 或相关文档，避免重复提案。
- 每次实验都要能指回日志或产物路径。
- 大结论进 `docs/agent/`，当前回合状态留在这里。
- 先把内容升格到 `docs/workflow/` memory 文件，再决定是否需要同步到 `docs/agent/`。
- 保持短小；如果一个文件开始写成长文，说明内容该迁移了。

## Tiny Helpers

- `scripts/new_experiment.sh "goal text"`
  - 在 `EXPERIMENT_LOG.md` 顶部插入一条新实验 stub。
- `scripts/new_ticket.sh ticket_name`
  - 由 `IMPLEMENTATION_TICKET_TEMPLATE.md` 复制一张时间戳 ticket。
