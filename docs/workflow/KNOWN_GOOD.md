# Known Good

这里只记录已经跑通过、或至少被反复确认可作为起点的命令和入口。

## Build And Debug

- 只编译 OpenSBI
  - `make opensbi`
- 只更新 Linux
  - `make linux-update`
- 只更新 Agent
  - `make agent-update`
- 启动调试环境
  - `make debug`
- 抓取日志
  - `make logger LOG=<tag>`
- 更新模块
  - `make modules-update`
- 非交互 wrapper 更新模块
  - `make modules-update-wrapper`

## Core Entrypoints

- 调试主入口文档：`docs/agent/SESSION_BOOTSTRAP.md`
- 当前状态入口：`docs/workflow/CURRENT_STATE.md`
- 当前测试计划：`docs/workflow/PLAN_20260322_container_validation.md`
- VM 自动命令配置：`config/vm_link.sh`
- tmux 调试入口：`config/tmux-debug.sh`
- 示例模块更新 wrapper：`docs/agent/nacc-modules-update.example.sh`

## Common Scenarios

- 最小 smoke：
  - `docker run --security-opt seccomp=unconfined --rm busybox echo test`
- same-PID re-exec：
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /tmp/test.txt"`
- fork smoke：
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"`

更系统的命令集合见 `PLAN_20260322_container_validation.md`。

## Reported Working Scenarios

这些命令目前有人工口头报告为“看起来可通过”，但仍待补准确 checkpoint 与日志路径。

- 2026-03-22 simple fork smoke：
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"`

## Reference Checkpoints

以下是 `docs/agent/SESSION_BOOTSTRAP.md` 中记录的历史关键检查点，只用于回退参考：

- 主仓：`5583d37`
- 主仓：`376462e`
- `linux/`：`45bba6df3a21`
- `opensbi/`：`38b0542`
- `opensbi/`：`ba828aa`
