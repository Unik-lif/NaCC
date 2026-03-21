# NaCC Workflow Layer

这层文档是给人和多个 agent 共用的轻量协作层。  
作用只有三个：
- 固定当前状态
- 固定下一步
- 固定角色边界

它不替代 `docs/agent/`：
- `docs/agent/` 放长期项目知识、稳定设计结论、关键代码入口
- `docs/workflow/` 放当前回合状态、计划、实验记录和协作文档

## 人类读者先看什么

如果你只想快速知道“项目现在在做什么”，按这个顺序看：

1. `CURRENT_STATE.md`
2. `NEXT_STEPS.md`
3. `PLAN_20260322_container_validation.md`
4. `PLAN_20260318_linux_friendly_fork.md`

这 4 个文件分别回答：
- 现在在做什么
- 接下来做什么
- 现在怎么测
- 长期方案往哪走

## 新会话最小阅读集

- `CURRENT_STATE.md`
- `NEXT_STEPS.md`
- `HYPOTHESES.md`

通常读完这 3 个文件，就够开始协作。

## 什么时候再读别的

- 想看长期决策：
  - `DECISIONS.md`
- 想看结构理解：
  - `ARCHITECTURE_NOTES.md`
  - `IMPLEMENTATION_NOTES.md`
- 想找可直接执行的命令：
  - `KNOWN_GOOD.md`
  - `PLAN_20260322_container_validation.md`
- 想看实验历史：
  - `EXPERIMENT_LOG.md`
- 想看角色边界：
  - `AGENT_PLANNER.md`
  - `AGENT_CODER.md`
  - `AGENT_LOG_ANALYZER.md`
  - `AGENT_PAPER_SCOUT.md`
  - `AGENT_TEST_RUNNER.md`
- 想看 guardrail：
  - `WORKFLOW_GUARDRAILS.md`
  - `HUMAN_OPERATOR_CHECKLIST.md`

## 推荐迭代循环

1. 先更新 `CURRENT_STATE.md`
2. 再看 `NEXT_STEPS.md`
3. 需要时修订 `HYPOTHESES.md`
4. 受控修改或测试
5. 结果写回 `EXPERIMENT_LOG.md`
6. 稳定结论再升格到 memory 文件

## 维护规则

- 先写状态，再开工
- 每次实验都要能指回日志或产物路径
- 当前回合状态留在 `docs/workflow/`
- 稳定结论再同步到 `docs/agent/`
- 如果一个文件开始写成长文，说明内容该迁移了

## 小工具

- `scripts/new_experiment.sh "goal text"`
  - 在 `EXPERIMENT_LOG.md` 顶部插入实验 stub
- `scripts/new_ticket.sh ticket_name`
  - 从 `IMPLEMENTATION_TICKET_TEMPLATE.md` 复制新 ticket
