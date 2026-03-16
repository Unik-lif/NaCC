# NaCC Session Bootstrap (Fast Start)

适用场景：新开对话窗口后，快速恢复上下文，不依赖历史长对话。

先看顺序建议：
1. 如果想知道“现在在做什么”，先看 `docs/workflow/CURRENT_STATE.md`
2. 如果想知道“这一轮接下来怎么协作”，再看 `docs/workflow/README.md`
3. 如果想知道“项目稳定设计和关键入口”，再读本文件
4. 若遇到大段原始日志，优先交给 log analyzer，会话不要混角色

配套长期知识库：
- `docs/agent/NACC_KNOWLEDGE_BASE.md`（状态机、常见告警根因、测试映射）
- `docs/agent/BITTER_LESSONS.md`（高代价反例，开工前先避免重复失误）

## 1. 当前项目基线（截至 2026-03-08）

- 主仓库：`/home/link/NaCC`
- 子仓库：
  - `linux/`（branch: `main`）
  - `opensbi/`（branch: `NoPIC`）
- 已推送的关键提交：
  - `linux`: `45bba6df3a21`  
    `[CODE]: nacc fork consume ptp_list and register child pagetable metadata`
  - `opensbi`: `38b0542`, `ba828aa`  
    `[CODE]: nacc fork emit packed child ptp_list for linux sync`  
    `[CODE]: ignore compile_commands artifacts in opensbi`
  - `NaCC` 主仓：`5583d37`, `376462e`  
    `[CODE]: add fork ptp_list notes and modules-update wrapper workflow`  
    `[CODE]: ignore compile_commands artifacts in root repo`

## 2. 关键设计结论（fork 元数据同步）

- NaCC parent fork 时，Linux 跳过常规 `copy_page_range()`，由 OpenSBI 复制用户页表树。
- 复制后，Linux 需要补齐 child 页表页 metadata（ptdesc/PTL ctor）。
- 当前采用 **OpenSBI 回传 `ptp_list`** 的方案，而不是 Linux 自行 walk child 页表：
  - 每个条目是 64-bit packed：`new_pfn + level`。
  - Linux 按 `level` 调 `pagetable_pmd_ctor/pagetable_pte_ctor`。
  - overflow 由 `nr_entries > capacity` 判定。

## 3. 关键代码入口（先看这些）

### Linux

- `linux/kernel/fork.c`
  - `dup_mmap()` 中 NaCC 分支调用 `nacc_fork(...)`。
- `linux/arch/riscv/kernel/sys_riscv.c`
  - `nacc_fork()`：分配 `ptp_list` 缓冲区、发起 SBI ecall、回收缓冲区。
- `linux/arch/riscv/mm/nacc.c`
  - `nacc_register_fork_ptp_list()`：解码 packed entry 并执行 ctor 注册。
- `linux/arch/riscv/include/asm/nacc.h`
  - `ptp_list` 结构与 packed 编解码宏。

### OpenSBI

- `opensbi/lib/sbi/sm/sm.c`
  - `sm_nacc_fork(..., ptp_list_pa, ptp_list_bytes)`。
- `opensbi/lib/sbi/sm/vm.c`
  - `nacc_fork_copy_user(...)` 与 `nacc_fork_ptp_list_push(...)`。
- `opensbi/lib/sbi/sbi_ecall_nacc.c`
  - `SBI_EXT_LINUX_FORK` 参数透传（含 ptp_list 地址和大小）。
- `opensbi/include/sm/vm.h`, `opensbi/include/sm/sm.h`
  - `ptp_list` 结构与函数签名。

## 4. 已知待关注项（新会话优先确认）

- `__pte_offset_map_lock()` 的 NaCC 分支防御性判空（`pte==NULL`）建议补上，避免异常路径 panic。
- `NACC_FORKED` 在 `exec_mmap` 前 reclaim 路径一致性需复核（与 `NACC_INITED` 对齐）。
- 目前是 prototype 语义：目标是 child 能稳定走到 `execve()`，不追求完整 Linux COW 语义。
- same-PID `re-exec` 先看 `docs/agent/NACC_KNOWLEDGE_BASE.md` 第 6 节：
  - agent 完整初始化链
  - trap 代理链
  - `sscratch/tp` 与 `__agent_exit/__trap_entry` 的关系

## 5. 构建与调试最短路径

- 仅 OpenSBI：
  - `PATH=/home/link/NaCC/riscv-tools/bin:$PATH make -C opensbi PLATFORM=generic CROSS_COMPILE=riscv64-unknown-linux-gnu- -j$(nproc)`
- 仅 Linux（推荐走项目 Makefile）：
  - `make linux-update`
- 调试循环：
  - `make debug`
  - `make logger LOG=<tag>`
  - 看 `logs/*qemu*.log`

## 6. sudo / 模块更新（已优化）

- 保留原流程：`make modules-update`
- 新增 wrapper 流程：`make modules-update-wrapper`
  - 默认调用：`sudo -n /usr/local/sbin/nacc-modules-update`
  - 示例脚本：`docs/agent/nacc-modules-update.example.sh`（全部绝对路径）

## 7. Git 协作约定（按当前习惯）

- 主仓常见：`git add record Makefile docs/agent`
- 子仓常见：
  - `cd linux` / `cd opensbi`
  - `git add *`
  - `git commit -m "[CODE]: ..."`
  - `git push`
- 推荐 message 风格：`[CODE]: <模块> <动作> <目的>`

## 8. 新会话开工 checklist

1. 先看本文件 + `docs/agent/README.md` + `docs/agent/NACC_KNOWLEDGE_BASE.md` + `docs/agent/BITTER_LESSONS.md`。  
2. `git -C linux status -sb`、`git -C opensbi status -sb`。  
3. 确认本次目标落在 Linux / OpenSBI / 主仓哪一层。  
4. 只改必要文件，尽量保持 patch 可 review。  
5. 改完先最小编译验证，再讨论是否提交/推送。  
