# Linux-Friendly Fork Plan

## Problem Statement

- 当前 NaCC fork 为绕过 secure page table 不可直接访问的问题，在 `dup_mmap()` 中跳过了标准 `copy_page_range()`，改由 OpenSBI 直接复制 child 用户页表树。
- 这条当前原型中的局部跳过/旁路实现已经帮助项目跨过了最初的 secure PTP 可见性障碍，但现在开始稳定暴露 Linux fork 语义缺口：
- child 页表页 `pgtables_bytes` 记账不闭环
- child leaf mappings 缺少标准 Linux fork 等价的 `rss` / `rmap` / `refcount` 建账
- 若继续把 fork 建立在“raw page-table copy + 零散补洞”上，后续想支撑 Ubuntu 级 workload 会面临不断累积的语义债和调试负担。

## Current Understanding

- 现有证据表明，child `ptp_list` 的 8 个页表页已经能正常注册，`ptdesc->ptl` 初始化问题已不再是首因。
- 当前更强的问题是：Linux fork 原本通过 `copy_page_range()` 建立的 metadata / accounting，没有在 NaCC 现有原型实现里被等价补齐。
- 日志中 `non-zero pgtables_bytes on freeing mm: -32768` 强烈指向 8 个 4 KiB PTP 页对应的页表页记账缺失。
- 日志中 `Bad rss-counter state`、后续 `Bad page map / state` 强烈指向 child leaf mappings 的 Linux accounting 缺口。
- 容器背景下的多进程共享内存是论文动机之一，因此 `mmap` / `MAP_SHARED` / shared memory 语义不是后续可选增强，而是长期方案必须覆盖的核心场景。
- 长期看，Ubuntu 级 workload 会大量放大 fork / exec / mmap / shared library / teardown 路径上的这些语义缺口。

## Constraints

- 长期方案要尽量 Linux-friendly，而不是继续扩张当前原型里的特化旁路实现。
- 不把正确性建立在大量运行期 trap 上；trap 只保留给真正 unavoidable 的 secure ownership / page fault / monitor 协作。
- Linux 侧应尽量直接走标准 fork 的读路径、walk 路径和 accounting 路径，而不是事后 replay 一套平行语义。
- OpenSBI 的职责应尽量收敛为“代 Linux 修改 secure 页表页”，而不是长期替 Linux 包办整个 fork 语义。
- 近期仍以 fork 主线为中心，不同时扩大战线到 reexec / init->exit。
- 当前已有先例表明，这种分工是可行的：Linux 可以读 secure 页表相关信息，只在真正写 secure 页表时借助 OpenSBI；`__pte_offset_map_lock` 一类路径已经采用了类似思路。

## Candidate Paths

### Path A: 保留当前原型里的局部旁路，只修本轮暴露的 accounting 洞

- 优点：
  - 短期 patch 最小
  - 能继续快速推进当前 fork+exec 场景
- 缺点：
  - 每遇到新 workload 都可能再暴露一类缺失语义
  - 容易把 fork 维护成越来越特化的分叉实现
  - 对 Ubuntu 级目标不友好

### Path B: 彻底回到标准 Linux fork，尽量不依赖 OpenSBI

- 优点：
  - 语义最接近上游
- 缺点：
  - 与 secure page table 的访问边界不兼容
  - 当前 NaCC 结构下实现成本高，且很可能不现实

### Path C: Linux 原生 fork 路线 + OpenSBI 写辅助

- Linux 尽量重新进入标准 fork 主线，尤其是 `copy_page_range()` 及其 accounting / COW / rmap 相关语义。
- 当 Linux 需要真正修改 secure 页表页时，由 OpenSBI 代写或辅助写入。
- 目标不是在 fork 后 replay 一套平行语义，而是让 Linux 原生 fork 路径尽量继续成立。

## Chosen Path

- 采用 Path C，作为长期方向。
- 对外描述为：**Linux-friendly fork**

定义：
- S-mode / Linux 尽量直接走标准 fork 读路径、walk 路径、accounting 路径和不变量建立路径。
- M-mode / OpenSBI 只在 Linux 需要修改 secure 页表页时提供代写能力。
- 长期目标不是 `semantic replay`，而是 **Linux 原生路径尽量不被当前原型里的局部旁路长期取代**。
- 运行期 trap 不再承担“主要正确性来源”，只处理必要的 NaCC 特殊边界。

## Rejected Alternatives And Why

- 不选择“继续长期坚持 raw copy + 零散补洞”：
  - 短期省事，长期会把每个 workload 都变成一次新的语义补洞工程。
- 不选择“靠很多 trap 把 fork 做绝”：
  - 这会把正确性分散到大量运行期路径，性能、复杂度和可调试性都更差。
- 不选择“完全不依赖 OpenSBI 地回退到标准 Linux fork”：
  - 当前 NaCC 的 secure page-table ownership 决定了这条路不现实。

## Staged Plan

### Stage 0: 收敛当前 fork accounting 首因

- 目标：
  - 明确 child 页表页账和 leaf 页账分别缺什么
- 产物：
  - 观测日志
  - 修复边界清单
- 退出条件：
  - 能明确回答：
    - `ptp_list` 注册是否漏了 `mm_inc_nr_ptes/mm_inc_nr_pmds`
    - child leaf mappings 是否漏了 `rss` / `rmap` / `refcount`
    - 当前哪些 fork 子步骤可以直接回到 Linux 原生路径，哪些步骤必须保留 OpenSBI 写辅助

### Stage 1: 补齐页表页 accounting

- 目标：
  - 让 child 的 PTP 页在 Linux 侧具备完整页表页记账闭环
- 重点：
  - `pgtables_bytes`
  - `mm_inc_nr_ptes`
  - `mm_inc_nr_pmds`
- 退出条件：
  - 不再出现与 child PTP 页数量对应的 `pgtables_bytes` 残值

### Stage 2: 补齐 child leaf fork accounting

- 目标：
  - 恢复标准 fork 对 child leaf mappings 的最小 Linux accounting 语义
- 优先项：
  - `rss`
  - `rmap`
  - `folio/page refcount`
  - 必要时检查 COW 写保护是否仍与 Linux 语义一致
- 设计原则：
  - 优先让 Linux 重新走标准 `copy_page_range()` 相关逻辑
  - 如果某一步只因“写 secure 页表”受阻，则改成 OpenSBI 写辅助，而不是整体跳过该步骤
  - 避免用大量 trap 在运行期慢慢修账

### Stage 2.5: 补齐容器共享内存 / `mmap` 关键语义

- 目标：
  - 验证并收敛容器场景下的 shared memory / `MAP_SHARED` / file-backed `mmap` 语义
- 为什么独立成阶段：
  - 这不是普通功能附带项，而是论文动机的一部分
  - 真实容器 workload 会在多进程共享映射和 `mmap` 路径上快速暴露语义缺口
- 通过标准：
  - parent/child 或 peer process 能稳定看到共享写入
  - teardown 后不出现计数与页状态损坏

### Stage 3: 形成稳定的 Linux 原生 fork + OpenSBI 写辅助模型

- 目标：
  - 把当前原型中的局部旁路实现收敛为长期可维护模型
- 形式：
  - Linux: 保持标准 fork 主线尽量成立
  - OpenSBI: 仅在 secure 页表写入点充当写辅助
- 退出条件：
  - fork+exec 不再依赖特定 demo 场景才能勉强走通
  - planner 可以把 fork 主线从“原型调通”切换到“语义稳定化”

### Stage 4: 再扩展到 reexec / init->exit / Ubuntu 级 workload

- 目标：
  - 在 fork 主线稳定后，再审计其他生命周期路径是否存在同类语义缺口
- 注意：
  - Ubuntu 不作为当前阶段目标
  - Ubuntu 是 Linux-friendly fork 足够成熟后的验收场景之一

### Stage 5: Security Hardening

- 目标：
  - 在基础语义和容器 workload 稳定后，再补做更偏安全 hardening 的项目
- 当前已知项：
  - `bitmap` 防护
- 顺序要求：
  - 不应早于 fork / `mmap` / shared memory 基础语义稳定

## Minimal Semantic Set To Restore

- 页表页层：
  - child PTP metadata
  - `pgtables_bytes`
- leaf 页层：
  - `rss`
  - `rmap`
  - `refcount`
- 共享 / COW 层：
  - 至少确认当前 NaCC 语义与 prototype 目标一致
  - 若未来升级为 Ubuntu 级目标，再继续补强
- 容器共享内存层：
  - `MAP_SHARED`
  - file-backed `mmap`
  - 匿名共享映射
  - 多进程 shared memory

## Native-Path Principle

- 优先问题不是“哪些语义要 replay”，而是“为什么 Linux 原生 fork 这一步没有继续走下去”。
- 若 Linux 已经能读取相关 secure 页表信息，就优先保留该读路径与上游语义。
- 只有当 Linux 需要真正写 secure 页表页，且该写入无法在 S-mode 直接完成时，才引入 OpenSBI 辅助。
- 对 coder 的默认要求是：
  - 先判断能否重新接回 `copy_page_range()` / `copy_pte_range()` / 相关 accounting 主线
  - 再最小化替换其中的 secure write 点
  - 不要默认设计一套“fork 后补账”的平行机制

## Immediate Next Actions

- 保持当前 P0/P1 聚焦在 fork accounting 观测与最小修复。
- coder 先不要扩大到 Ubuntu、reexec 或 init->exit。
- planner 在 Stage 1/2 观测结束后，再决定 Linux 原生 fork 主线该如何接回：
  - A. 直接恢复更多 `copy_page_range()` 子路径
  - B. 保留 Linux walk/accounting，只把 secure write 点委托给 OpenSBI
  - C. 仅在极少数无法接回的点保留临时旁路

## Notes For Other Agents

- coder:
  - 当前默认目标不是“继续维护当前原型里的局部旁路”，也不是“设计 replay 层”，而是把 fork 向 Linux 原生路径收敛。
  - 优先思考如何让 Linux 重新走 `copy_page_range()` 一侧的主语义，只把 secure write 委托给 OpenSBI。
  - 不要把修复建立在引入很多新 trap 上。
- log analyzer:
  - 继续以 fork accounting 首个异常点为准，不再把旧的 `ptdesc->ptl` 问题当首因。
- planner:
  - 后续所有 fork 方案比较，都优先评估“是否更接近 Linux 原生 fork 路径、是否只在必要写点依赖 OpenSBI”。
