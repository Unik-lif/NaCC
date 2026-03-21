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

### fork 长期模型：Linux-friendly fork

- 当前原型里的局部旁路实现，其工程价值主要在于跨过 secure page-table 不可直接访问的初始障碍，而不是作为最终 fork 设计。
- 长期目标不是“完全回到标准 Linux fork”，也不是“靠越来越多 trap 把当前原型里的旁路缝完整”。
- 当前接受的方向是：
  - Linux 尽量直接恢复标准 fork 的 read / walk / accounting 主线
  - OpenSBI 仅在 secure 页表写入点充当写辅助
- 这不是 `semantic replay` 模式；目标是尽量不打断 `copy_page_range()` 一侧的原生语义。
- 长期最小恢复集合包括：
  - child PTP 页表页记账
  - child leaf mappings 的 `rss` / `rmap` / `refcount`
  - 必要的 COW / shared mapping 语义一致性
- 容器场景下的多进程共享内存与 `mmap` 是论文动机的一部分，因此不应被当作“后面再顺手测一下”的附属能力。
- 这类设计在项目中已有局部先例：Linux 可以直接走读路径，写 secure 页表时再切到 OpenSBI 辅助，例如 `__pte_offset_map_lock` 一类处理。
- Ubuntu 级 workload 被视为该模型成熟后的验收场景，而不是当前阶段目标。
