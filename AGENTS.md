# NaCC 项目全局规则

## 快速指路
- 新会话先看：`docs/workflow/CURRENT_STATE.md`
- 需要知道怎么协作：`docs/workflow/README.md`
- 需要当前多角色执行流：`docs/workflow/HARNESS_V2.md`
- 需要下一阶段自动化规划：`docs/workflow/HARNESS_V2_PLAN.md`
- 人类最简启动入口：`docs/workflow/HUMAN_BOOTSTRAP.md`
- 需要当前稳定技术背景：`docs/agent/SESSION_BOOTSTRAP.md`
- 需要长期知识：`docs/agent/NACC_KNOWLEDGE_BASE.md`、`docs/agent/BITTER_LESSONS.md`
- 要跑一轮编译 + debug + logger：`docs/workflow/AGENT_TEST_RUNNER.md`
- 看日志前先确认会话角色是否正确；大段原始日志优先交给 log analyzer
- 要改代码但还没有清晰任务时，先补：`goal / scope / constraints / definition of done`

## 项目概述
NaCC（Native Confidential Container）是一个基于 RISC-V 的机密容器框架，通过 M-mode OpenSBI Monitor 实现页表隔离保护。项目根目录为 `/home/link/NaCC`。

## 关键目录
- `linux/`：定制化 Linux 内核源码（含 NaCC 钩子）
- `opensbi/`：定制化 OpenSBI 源码（含 NaCC Monitor）
- `agent/`：NaCC Agent（bare-metal，和linux同一个特权级，管理安全页表页）
- `config/`：调试配置（GDB、tmux、VM 连接脚本）
- `logs/`：测试日志归档
- `record/`：开发记录和分析文档

## 编码约定
- 内核代码：NaCC 相关函数以 `nacc_` 为前缀
- OpenSBI 代码：NaCC 相关函数以 `sbi_nacc` 为前缀
- Agent 代码：使用 bare-metal RISC-V 汇编和 C

## Working Language
- Use English for agent-user communication by default.
- Use English for analysis reports, planning notes, and newly added documentation unless the user explicitly asks for another language.
- Code comments may be written in English or Chinese, but English is preferred for new comments.
- Existing Chinese documents may remain as historical project material; do not rewrite them unless the task requires it.

## 其他项目资产
- .agent文件夹是先前让gemini和claude一起整理的SKILL.md，没准对你来说有用
- record是作者的工作进度记录，包括一些调试结论和思考
- src_analysis有一些作者自己读代码时的体悟，但是可能有些过时，需要辩证看待

## 注意事项
- 修改内核代码后需要重编译：`make linux-update`
- 修改 OpenSBI 代码后需要重编译：`make opensbi`
- 修改 Agent 代码后需要重编译：`make agent-update`
- 不要直接修改 `riscv-linux/` 或 `riscv-qemu/` 等编译输出目录
- 日志文件可能很大（数万行），分析时优先查看关键事件

## 新会话快速入口
- 新开窗口优先阅读：
  - `docs/workflow/CURRENT_STATE.md`
  - `docs/workflow/README.md`
  - `docs/workflow/HARNESS_V2.md`
  - `docs/workflow/HUMAN_BOOTSTRAP.md`
  - `docs/agent/SESSION_BOOTSTRAP.md`
- 当前工作状态先看 `docs/workflow/`
- 稳定设计和关键代码入口再看 `docs/agent/`
