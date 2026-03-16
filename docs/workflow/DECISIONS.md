# Decisions

只记录已经明确采用、并会影响后续工作的决定。

维护规则：
- planner 是主维护者。
- 其他角色可以提交候选条目，但不直接把临时猜测写成长期决策。
- 每条都应带上依据，最好能指向日志、ticket、记录或代码。

## Entry Template

### [Date] Decision Title

- Status: proposed / accepted / superseded
- Decision:
- Why:
- Evidence:
- Impact:
- Supersedes:

## Current Entries

### [2026-03-17] `docs/workflow/` 作为当前工作流层

- Status: accepted
- Decision: 把共享状态、交接模板、guardrail 和项目记忆放在 `docs/workflow/`，而不是 `.agent/`
- Why: 这层内容主要服务仓库协作和人工维护，应与工具私有目录分开
- Evidence: 当前仓库里 `docs/agent/` 已承担项目知识层，`.agent/` 更像历史规则和工作流碎片
- Impact: 未来会话先看 `docs/workflow/` 的当前状态与长期记忆，再按需进入 `docs/agent/`
- Supersedes:
