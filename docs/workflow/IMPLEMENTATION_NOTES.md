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
