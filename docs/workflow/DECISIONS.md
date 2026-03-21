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

### [2026-03-18] fork 长期方向转向 Linux 原生路径 + OpenSBI 写辅助

- Status: accepted
- Decision: 不再把当前的 `raw page-table copy + 长期零散补洞` 视为 fork 最终模型；长期方向改为“Linux 尽量走原生 fork 主线，只在 secure 页表写入点依赖 OpenSBI”
- Why:
  - 当前原型中的局部旁路实现已稳定暴露 `pgtables_bytes` 与 child leaf accounting 缺口
  - 若未来希望承载 Ubuntu 级 workload，继续维护这类特化旁路的长期成本会更高
  - 项目已有先例说明 Linux 可以读取相关 secure 页表信息，只在写点借助 OpenSBI
  - `semantic replay` 容易误导 coder 走平行实现，而非回接 Linux 原生路径
- Evidence:
  - `logs/fork_exec_default_freshwait_20260317_qemu_20260317_151037.log`
  - `docs/workflow/PLAN_20260318_linux_friendly_fork.md`
- Impact:
  - coder 后续修 fork 时，应优先考虑重新接回 `copy_page_range()` 一侧的标准 Linux 语义
  - OpenSBI 的职责应尽量收敛为 secure 页表写辅助，而非长期包办整个 child page-table copy 语义
  - planner 在方案比较时，应把“是否更接近 Linux 原生路径、是否仅在必要写点依赖 OpenSBI”作为主评估标准
- Supersedes:
  - 隐含地替代“当前原型里的局部旁路可直接演化为最终 fork 模型”的默认假设
  - 同时澄清并替代此前容易被理解为 `Linux semantic replay` 的模糊表述

### [2026-03-17] `docs/workflow/` 作为当前工作流层

- Status: accepted
- Decision: 把共享状态、交接模板、guardrail 和项目记忆放在 `docs/workflow/`，而不是 `.agent/`
- Why: 这层内容主要服务仓库协作和人工维护，应与工具私有目录分开
- Evidence: 当前仓库里 `docs/agent/` 已承担项目知识层，`.agent/` 更像历史规则和工作流碎片
- Impact: 未来会话先看 `docs/workflow/` 的当前状态与长期记忆，再按需进入 `docs/agent/`
- Supersedes:
