# Implementation Ticket

## Goal

- 为 NaCC `fork` 重做建立明确起点，避免后续 coder 继续沿用当前 `skip copy_page_range() + OpenSBI 全树复制` 的原型思路。
- 把“哪些旧实现需要退回”、“哪些资产可以复用”、“第一阶段编码应先接回哪条 Linux 主线”固定下来。

## Background

- 当前 Linux 在 [`linux/kernel/fork.c`](/home/link/NaCC/linux/kernel/fork.c) 的 `dup_mmap()` 中，一旦父进程带 `NACC_INITED`，就设置 `nacc_skip_copy_page_range`，跳过每个 VMA 的 `copy_page_range()`，最后再调用 `nacc_fork(...)`。
- 当前 [`linux/arch/riscv/kernel/sys_riscv.c`](/home/link/NaCC/linux/arch/riscv/kernel/sys_riscv.c) 的 `nacc_fork()` 只负责：
  - 发起 `SBI_EXT_NACC_FORK`
  - 接收 `ptp_list`
  - 调 `nacc_register_fork_ptp_list()` 给 child PTP 补 ctor / metadata
- 当前 [`opensbi/lib/sbi/sm/vm.c`](/home/link/NaCC/opensbi/lib/sbi/sm/vm.c) 的 `nacc_fork_copy_user()` 在 M-mode 递归复制 child 用户页表树，并直接复制 leaf PTE、分配 child non-leaf PTP、对可写 leaf 做 wrprotect。
- 现有状态文件和日志已经把长期方向固定为：
  - Linux 尽量回到原生 `copy_page_range()` / accounting 主线
  - OpenSBI 只在 secure 页表写入点提供写辅助

## Problem Statement

- 当前原型绕开了 Linux 原生 fork 最关键的一段语义建立路径：
  - child 页表页记账
  - child leaf `rss`
  - `rmap`
  - `folio/page refcount`
  - 与 `copy_page_range()` 绑定的 COW/shared mapping 细节
- 这不是单点补洞能稳定解决的问题；继续以 OpenSBI 全树复制为主线，只会让 Linux 语义缺口持续外溢到 teardown、reclaim 和更多 workload。

## Must Stop Relying On

- 把 `dup_mmap()` 里的“整段跳过 `copy_page_range()`”当作 NaCC fork 主实现。
- 把 OpenSBI 的 `nacc_fork_copy_user()` 当作长期 child 用户页表复制主线。
- 把 `ptp_list` 后补 ctor / metadata 当作对 Linux fork 主语义的充分替代。
- 继续按“先 raw copy，再逐项补 replay/accounting”扩展实现。

## Reusable Assets

- `NACC_FORKED` 这条 task 身份链仍可保留；它解决的是 child 生命周期分流，不是 fork 复制语义本身。
- `VM_DONTCOPY` / `VM_WIPEONFORK` / `VM_NACC` 这些过滤语义仍然有效，但应回到 Linux 主线里决定“哪些映射不该复制”，而不是让 OpenSBI 长期包办整棵树。
- [`linux/arch/riscv/mm/nacc.c`](/home/link/NaCC/linux/arch/riscv/mm/nacc.c) 里的：
  - `page_nacc_mappings()`
  - `page_nacc_register_ptp()`
  - `nacc_reclaim_ptp_dtor()`
  可以继续作为 secure PTP 生命周期辅助件使用，但不应再只服务于“OpenSBI 复制后补注册”。
- [`linux/mm/pgtable-generic.c`](/home/link/NaCC/linux/mm/pgtable-generic.c) 里已有 `__pte_offset_map_lock()` 的 NaCC 分支，说明 Linux 侧读 / walk secure PTP 并非不可行；后续应优先扩大这种模式，而不是继续扩大 bypass。

## Stage 1 Coding Target

- 目标不是“一次性做完 fork”，而是先把主语义入口接回 Linux：
  1. 让 NaCC fork 不再整段跳过 `copy_page_range()`
  2. 用实际代码路径找出 `copy_page_range()` / `copy_pte_range()` 中真正因 secure ownership 卡住的写点
  3. 仅把这些写点替换为 NaCC helper 或 SBI 写辅助
  4. 保持 leaf accounting、rmap、refcount 尽量继续由 Linux 原生路径承担

## First Cut Boundaries

- 第一刀优先动 Linux，不先重写 OpenSBI：
  - [`linux/kernel/fork.c`](/home/link/NaCC/linux/kernel/fork.c)
  - [`linux/mm/memory.c`](/home/link/NaCC/linux/mm/memory.c)
  - [`linux/mm/pgtable-generic.c`](/home/link/NaCC/linux/mm/pgtable-generic.c)
  - [`linux/arch/riscv/include/asm/pgtable.h`](/home/link/NaCC/linux/arch/riscv/include/asm/pgtable.h)
  - [`linux/arch/riscv/mm/nacc.c`](/home/link/NaCC/linux/arch/riscv/mm/nacc.c)
- OpenSBI 第一阶段只接受“更窄的 helper 接口”，不再新增“替 Linux 完成整棵用户页表复制”的能力。

## Non-Goals

- 这一轮不要求立刻覆盖 Ubuntu 级 workload。
- 不同时扩到 `reexec`、`init->exit`、通用 trap 体系。
- 不要求一次性删光旧的 `ptp_list` / `nacc_fork_copy_user()` 代码；允许先退居 fallback 或历史路径，但不能继续作为默认正确性来源。

## Definition Of Done

- 后续真正开工实现时，应以这几个退出条件为准：
  - NaCC fork 主线不再依赖“跳过 `copy_page_range()` 后再整体 SBI copy”
  - 能列出 `copy_page_range()` 主线上被 secure ownership 阻断的具体写点，而不是笼统描述“Linux 不能碰 secure 页表”
  - OpenSBI 职责收敛成少量、明确、可枚举的写辅助接口
  - 设计默认由 Linux 原生路径承担 child leaf accounting，而不是 fork 后补 replay

## Validation Hook

- 代码入口：
  - [`linux/kernel/fork.c`](/home/link/NaCC/linux/kernel/fork.c)
  - [`linux/mm/memory.c`](/home/link/NaCC/linux/mm/memory.c)
  - [`opensbi/lib/sbi/sm/vm.c`](/home/link/NaCC/opensbi/lib/sbi/sm/vm.c)
- 运行验证仍沿用当前 fork+exec 关键场景：
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"`

## Notes For Next Coding Turn

- 如果下一轮是纯编码会话，默认先做“恢复 Linux `copy_page_range()` 主线 + 打点找 secure 写点”。
- 如果下一轮仍以日志证据为主，继续沿用当前 accounting 观测 ticket，但不要再把“修完 `ptp_list` 注册”误判为 fork 主线已接近完成。
