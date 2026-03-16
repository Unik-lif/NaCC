# NaCC Agent Collaboration Notes

这份文档是把 `AGENT.md` 与 `.agent/` 中可复用信息，整理成当前仓库的实用协作手册，便于后续快速迭代。

会话切换时请先看：

- `docs/agent/SESSION_BOOTSTRAP.md`
- `docs/agent/NACC_KNOWLEDGE_BASE.md`（长期稳定结论）
- `docs/agent/BITTER_LESSONS.md`（高代价反例，先避免重复踩坑）
- `docs/agent/REEXEC_DEBUG_20260312.md`（3 月 12 日这轮 same-PID `reexec` 收敛结果）
- `docs/agent/FORK_DEBUG_20260315.md`（3 月 15 日这轮 fork+exec 主线收敛结果）

## 1. 项目事实（长期有效）

- 核心代码目录：
  - `linux/`：NaCC 内核钩子与 mm/fork/exec/reclaim 逻辑
  - `opensbi/`：M-mode monitor 与 SBI 扩展实现
  - `agent/`：bare-metal agent
- 构建输出目录：
  - `riscv-linux/`, `riscv-qemu/`, `riscv-linux-modules/`（尽量不手改）
- 主要交流语言：中文（代码注释中英文均可）

## 2. 高效工作流

### 2.1 改完代码后的最小编译策略

- 只改 OpenSBI：
  - `make opensbi`
- 只改 Linux：
  - `make linux-update`
- 只改 Agent：
  - `make agent-update`

### 2.2 调试循环

1. `make debug` 启动 tmux 三分屏（QEMU/VM/GDB）。
2. 复现实验。
3. `make logger LOG=<tag>` 抓日志。
4. 重点看 `logs/*qemu*.log` 的 Oops、page fault、fork/exec/reclaim 轨迹。

### 2.3 关键排查点（NaCC 相关）

- `thread.nacc_flag` 状态流是否正确：
  - `NACC_PREPARE -> NACC_INITED -> (fork child) NACC_FORKED -> NACC_RECLAIM`
- fork 路径是否完成：
  - OpenSBI 复制页表
  - Linux 同步页表页 metadata（ctor/PTL）
- exec/exit 回收是否走 NaCC 分支，避免普通 `kmem_cache_free` 路径误用。

## 3. 免密 sudo / 非交互 sudo

`make modules-update` 已支持通过变量覆盖 sudo 命令：

- 默认行为（不变）：`make modules-update`（使用 `sudo`）
- 非交互失败即退出：`make modules-update SUDO="sudo -n"`
- 已在 root shell 中运行：`make modules-update SUDO=""`

建议给当前用户配置最小权限 NOPASSWD（仅限必要命令），避免给全量 sudo 免密。

### 3.1 Wrapper 脚本（绝对路径版）

仓库内提供了示例脚本：
- `docs/agent/nacc-modules-update.example.sh`

推荐安装为 root 可执行脚本：

1. `sudo install -m 750 -o root -g root docs/agent/nacc-modules-update.example.sh /usr/local/sbin/nacc-modules-update`
2. `sudo visudo -f /etc/sudoers.d/nacc-modules-update`
3. 写入（把 `link` 改成你的用户名）：
   - `link ALL=(root) NOPASSWD: /usr/local/sbin/nacc-modules-update`

### 3.2 Makefile 新增入口

保留原 `modules-update` 流程不变，新增：
- `make modules-update-wrapper`

默认使用：
- `ROOT_SUDO="sudo -n"`
- `NACC_MODULES_UPDATE_WRAPPER="/usr/local/sbin/nacc-modules-update"`

可覆盖示例：
- `make modules-update-wrapper ROOT_SUDO="sudo -n" NACC_MODULES_UPDATE_WRAPPER="/usr/local/sbin/nacc-modules-update"`

## 4. 后续建议

- 把每次 crash 根因和修复动作沉淀到 `record/*.md`，避免同类回归重复分析。
- 若 fork/exec 路径再次变更，优先更新本目录文档，再改实现。
- 长期稳定结论优先写入 `docs/agent/NACC_KNOWLEDGE_BASE.md`，避免只留在临时记录里。
- 高代价误判、错日志、错回滚这类反例，优先写入 `docs/agent/BITTER_LESSONS.md`。

## 5. Git 协作约定（当前）

### 5.1 主仓库（NaCC）

- 常见操作：
  - `git add record Makefile docs/agent`
  - `git commit -m "<message>"`
- 推荐 message（比 `update` 更可读）：
  - `[CODE]: update workflow docs and build wrapper targets`

### 5.2 子仓库（linux/opensbi/agent/qemu）

- 常见操作（按你的习惯）：
  - `cd linux`
  - `git add *`
  - `git commit -m "[CODE]: xxxxx"`
  - `git push`

建议后续 commit message 直接描述“模块 + 动作 + 目的”：
- `linux`: `[CODE]: nacc fork consume ptp_list and register pagetable metadata`
- `opensbi`: `[CODE]: nacc fork emit packed child ptp_list for linux sync`
