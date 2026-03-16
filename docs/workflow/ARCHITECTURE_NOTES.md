# Architecture Notes

记录需要多轮复用的结构性理解，不写一次性调试细节。

维护规则：
- planner 负责整理成长期可读版本。
- coder / log analyzer / paper scout 只提交候选理解和证据。
- 如果内容已经非常稳定且更适合进入项目知识库，可再同步到 `docs/agent/`。

## Suggested Sections

- 关键组件与边界
- 状态机与不变量
- 关键调用链
- 关键 ownership / lifecycle
- 当前仍开放的问题

## Current Notes

### 双层状态

- NaCC 既有 Linux 侧 `thread.nacc_flag`，也有运行时 `CSR_NACC_STATE`
- 两层若不同步，会导致“Linux 认为已进入 NaCC，但运行时状态不匹配”的问题
- 更完整说明见 `docs/agent/NACC_KNOWLEDGE_BASE.md`

### fork+exec 当前结构焦点

- parent fork 时，Linux 跳过常规 `copy_page_range()`
- OpenSBI 复制 child 用户页表树
- Linux 需要补齐 child 页表页 metadata / ctor / ptlock 语义
- 当前长期关注点是 child PTP 生命周期是否真正闭环
