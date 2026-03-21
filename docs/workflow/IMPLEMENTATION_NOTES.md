# Implementation Notes

记录会影响后续编码的实现级事实，但不替代 ticket 和 commit message。

维护规则：
- coder 可提交候选条目。
- planner 负责决定哪些实现事实要升级成 durable memory。
- 只写跨多轮仍有用的实现约束、入口和坑点。

## Entry Template

### Topic: <name>

- Relevant Files:
- Implementation Fact:
- Why It Matters:
- Validation Hook:
- Source:

## Current Notes

### Topic: fork `ptp_list` 同步链

- Relevant Files:
  - `linux/arch/riscv/kernel/sys_riscv.c`
  - `linux/arch/riscv/mm/nacc.c`
  - `opensbi/lib/sbi/sm/sm.c`
  - `opensbi/lib/sbi/sm/vm.c`
- Implementation Fact:
  - OpenSBI 会回传 child `ptp_list`
  - Linux 负责解码并补 ctor 注册
- Why It Matters:
  - 这是当前 fork+exec 调试主线的核心交界面
- Validation Hook:
  - `nacc_register_fork_ptp_list()`
  - OpenSBI `ptp_list push`
- Source:
  - `docs/agent/SESSION_BOOTSTRAP.md`

### Topic: fork 长期不再以当前原型旁路为终点

- Relevant Files:
  - `linux/kernel/fork.c`
  - `linux/mm/memory.c`
  - `linux/arch/riscv/mm/nacc.c`
  - `opensbi/lib/sbi/sm/vm.c`
- Implementation Fact:
  - 长期 fork 方向是“Linux 尽量走原生 `copy_page_range()` / accounting 主线，只把 secure 页表写点委托给 OpenSBI”，而不是维持 `skip copy_page_range() + 长期零散补洞`
- Why It Matters:
  - 这决定了后续修复应优先接回 Linux 原生 fork 路径，而不是继续堆叠运行期 trap 或另写 replay 层
- Validation Hook:
  - child `pgtables_bytes`
  - child leaf `rss` / `rmap` / `refcount`
  - 是否能让 `copy_page_range()` 一侧重新承担更多原职责
- Source:
  - `docs/workflow/PLAN_20260318_linux_friendly_fork.md`
