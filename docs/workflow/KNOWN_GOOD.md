# Known Good

这里只记录已经跑通过、或至少被反复确认可作为起点的命令和入口。

## Commands That Work

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

## Configs That Work

- 调试主入口文档：`docs/agent/SESSION_BOOTSTRAP.md`
- VM 自动命令配置：`config/vm_link.sh`
- tmux 调试入口：`config/tmux-debug.sh`
- 示例模块更新 wrapper：`docs/agent/nacc-modules-update.example.sh`

## Known Bootable Checkpoints

以下是 `docs/agent/SESSION_BOOTSTRAP.md` 中记录的已推送关键检查点，作为回退参考：

- 主仓：`5583d37`
- 主仓：`376462e`
- `linux/`：`45bba6df3a21`
- `opensbi/`：`38b0542`
- `opensbi/`：`ba828aa`

使用前应由人再次确认这些检查点仍符合当前实验目标。

## Reproducible Debug Entrypoints

- 启动三分屏调试：
  - `make debug`
- 采集最新日志：
  - `make logger LOG=<tag>`
- 最新日志入口：
  - `logs/nacc_qemu_20260316_221143.log`
  - `logs/nacc_vm_20260316_221143.log`

## Scenario Shortcuts

来自 `docs/agent/NACC_KNOWLEDGE_BASE.md` 的常用场景：

- 最小 smoke：
  - `docker run --security-opt seccomp=unconfined --rm busybox echo test`
- same-PID re-exec：
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /tmp/test.txt"`
- fork+exec 关键场景：
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"`
