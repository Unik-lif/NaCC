# NaCC 长期知识库（fork/exec/re-exec/mm）

> 目的：沉淀“已经反复验证过”的事实，减少重复踩坑。  
> 更新原则：仅记录稳定结论；实验性猜测放 `record/*.md`。

## 1. 双层状态机（必须同时看）

NaCC 实际有两层状态：

1. Linux 进程语义状态：`thread.nacc_flag`
2. 运行时硬件状态：`CSR_NACC_STATE`（QEMU/OpenSBI）

若两层不同步，会出现“Linux 认为是 NaCC，QEMU 认为不是”的卡住症状。

### 1.1 Linux `nacc_flag`

- `NACC_PREPARE = 0b001`
- `NACC_INITED = 0b010`
- `NACC_RECLAIM = 0b100`
- `NACC_FORKED = 0b1000`
- `NACC_REEXEC = 0b10000`

典型链路：

```text
NORMAL -> PREPARE -> INITED
INITED --(same PID exec)--> REEXEC -> INITED
INITED --(fork child)--> child:FORKED --(child exec)--> INITED
INITED --(exit/exec teardown)--> RECLAIM
```

### 1.2 `CSR_NACC_STATE`

- `INACTIVE`
- `AGENT`
- `LINUX`
- `MONITOR`

关键约束：

- `aret` 只在 `nacc_state == LINUX` 有效；否则 QEMU 会打印：
  - `Not in nacc process linux state. Simply omit it.`

---

## 2. 关键不变量（当前版本）

1. 只要一个 `mm` 持有 NaCC 安全 PTP，销毁前必须先进入 `RECLAIM` 语义。
2. `INITED` 只能在 re-attach SBI 调用成功后设置，避免 trap 时序错窗。
3. `nacc_flag` 是位标志，涉及组合态时不能依赖单纯 `==` 做状态分支。

### 2.1 2026-03-16 补充：`thread.nacc_flag` 与 `mm` 回收状态不要继续混用

- 这轮 fork 调试暴露出的一个稳定结论是：`thread.nacc_flag` 更适合表达 task 执行态（如 `PREPARE/INITED/REEXEC`），不适合继续独占承载地址空间 teardown 策略。
- `exit_mmap()`、`unmap_page_range()`、`free_pgtables()` 处理的是 `mm/VMA` 生命周期；若 special reclaim 是否命中仍只依赖 `current->thread.nacc_flag`，很容易因为某条隐蔽路径漏置位而把整个 `mm` 释放带偏。
- 后续状态机应优先向“两层”收敛：
  - task 侧保留 NaCC 执行态
  - mm 侧补充 NaCC 地址空间/回收态
- 当前已明确支持的场景只有：
  - 纯 builtin 常规路径
  - same-PID reexec 路径
  fork 路径先不纳入这条长期结论的实现范围。

---

## 3. 高频告警的真实含义

## 3.1 `BUG: Bad rss-counter state`

触发点：

- `__mmdrop()` 末尾 `check_mm()` 对 `mm->rss_stat[]` 做一致性检查。

本质：

- `rss_stat` 和真实映射数量不一致（非 0、或被减成负数）。

NaCC 语境下高概率原因：

- fork bypass 跳过 `copy_page_range()`（Linux 不再给 child 做 RSS 记账），
- 但 OpenSBI 又复制了 PTE，导致“有映射但没加账”，退出时再减账出现异常值。

---

## 3.2 `BUG: Bad page state in process ... pfn:xxxxx`

触发点：

- 页回收到 buddy 前，`free_pages_prepare()` 检查 `struct page` 不满足预期。

本质：

- page 元数据不一致：`mapcount/refcount/mapping/flags` 有残留或错配。

NaCC 语境下常见两类：

1. PFN 落在 NaCC PTP 区间（如 `0x1b0000-0x1c0000`）却走了普通释放路径。
2. 普通数据页在 fork bypass 后没有补齐 Linux 元数据（rmap/refcount/COW），
   teardown 时出现 put/free 失衡。

---

## 4. 测试命令到场景映射（`config/vm_link.sh`）

以下命令可直接复用，日志请带场景标签。

### 4.1 直接执行（最小路径）

命令：

```bash
docker run --security-opt seccomp=unconfined --rm busybox echo test
```

场景：

- 非 `sh -c`，用于验证注册/初始化/退出回收最短链路。

建议日志标签：

- `smoke_echo`

### 4.2 re-exec（同 PID）最小复现

命令：

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /tmp/test.txt"
```

场景：

- `sh -c` 单外部命令，busybox 常走同 PID re-exec。

建议日志标签：

- `reexec_cat_only`

### 4.3 re-exec（builtin + 外部命令）

命令：

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "echo hello > /tmp/test.txt && cat /tmp/test.txt"
```

场景：

- 前半 builtin，后半外部命令，常用于观察 re-exec 中间态。

建议日志标签：

- `reexec_builtin_plus_cat`

### 4.4 builtin 对照组

命令：

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c 'echo hello; echo b; echo c'
```

场景：

- 纯 builtin，通常无 fork / 无 re-exec，适合作为低变量对照。

建议日志标签：

- `builtin_only`

### 4.5 fork+exec 关键场景

命令：

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"
```

场景：

- 父 shell 需要继续执行 `echo done`，典型 fork+exec 检查命令。

建议日志标签：

- `fork_exec_cat_then_echo`

---

## 5. 代码入口速查（优先级顺序）

Linux：

- `linux/fs/exec.c`
  - `begin_new_exec`（exec 前后 flag/reclaim 转移）
  - `bprm_execve` 尾部（`nacc_invoke` / `nacc_invoke_child`）
- `linux/kernel/fork.c`
  - `dup_mmap`（NaCC fork bypass + `nacc_fork`）
- `linux/arch/riscv/kernel/process.c`
  - `copy_thread`（child `NACC_FORKED`）
- `linux/mm/memory.c`
  - `unmap_page_range`、`zap_pte_range`、`free_pte_range`
- `linux/kernel/exit.c`
  - `exit_group`（reclaim 入口）
- `linux/arch/riscv/kernel/traps.c`
  - `do_trap_ecall_u` / `do_page_fault` / `do_irq` 的 aret 触发点

OpenSBI/QEMU：

- `opensbi/lib/sbi/sm/sm.c`
  - `sm_nacc_invoke` / `sm_nacc_invoke_child` / `sm_nacc_fork`
- `opensbi/lib/sbi/sm/vm.c`
  - `nacc_fork_copy_user`（leaf wrprotect / child PTP 分配）
- `qemu/target/riscv/op_helper.c`
  - `helper_aret`（`nacc_state != LINUX` 直接 omit）

---

## 6. Agent 初始化与 Trap 代理链

这一部分是 same-PID re-exec 讨论中最容易混淆的地方：  
“agent 启动一次”与“后续每次用户 trap 都先经过 agent”不是一回事。

### 6.1 完整初始化链

入口：

- OpenSBI `agent_prepare(...)`
  - `opensbi/lib/sbi/sm/agent.c`
- Agent `_entry`
  - `agent/src/entry.S`
- Agent `main()`
  - `agent/src/main.c`
- `vm_init()`
  - `agent/src/vm.c`

完整初始化时发生的事：

1. OpenSBI 通过 `agent_prepare(...)` 把下面这些 Linux 侧锚点传给 agent：
   - `_user_pt_regs`
   - `_do_irq`
   - `_excp_vect_table`
   - `_current_gp`
   - 以及页表切换所需的 `offset/satp`
2. Agent `_entry` 只负责把这些值写进 agent 全局变量，然后进入 `main()`
3. `main()` 走 `mem_init()` + `vm_init()`
4. `vm_init()` 建 agent 临时页表，切换回 Linux 页表语境
5. `trap_init()` 安装后续 trap 代理入口
6. `__agent_exit(_user_pt_regs)` 第一次把用户态上下文恢复出去

结论：

- `agent_prepare -> _entry -> main -> vm_init` 是一条“完整初始化链”
- 这条链很重，不应默认用于 same-PID re-exec

### 6.2 Trap 代理链

真正保护机密进程用户态上下文的关键，不在 `main()`，而在下面三段：

- `trap_init()` in `agent/src/trap.c`
- `__trap_entry` in `agent/src/entry.S`
- `__ret_from_exception` / `__agent_exit` in `agent/src/entry.S`

语义如下：

1. `trap_init()`
   - 分配 `_user_context`
   - 写 `CSR_TWIN_ENTRY = __trap_entry`
2. 用户态再次 trap 时，先进入 `__trap_entry`
3. `__trap_entry`：
   - 先 `csrrw tp, CSR_SSCRATCH, tp`
   - 依赖 `sscratch` 中已经放好的 Linux kernel `tp`
   - 把用户寄存器保存到 agent 私有 `_user_context`
   - 再复制到 Linux 期望的 `pt_regs`
   - 最后通过 `_do_irq` 或 `_excp_vect_table` 跳回 Linux
4. Linux 异常返回时，经 `__ret_from_exception`
   - 重新设置 `CSR_SSCRATCH`
   - 恢复用户寄存器
5. 首次从 agent 进入用户态则走 `__agent_exit(_user_pt_regs)`

结论：

- 用户态上下文真正的“安全副本”在 agent 私有 `_user_context`
- Linux 看到的 `pt_regs` 是 agent 拷贝出来的视图
- `sscratch/tp` 约定是整条 trap 代理链能工作的重要前提

### 6.3 对 same-PID re-exec 的直接启发

当前稳定判断：

1. same-PID re-exec 的首要问题更像是“trap 出口/入口上下文没有接回去”，不是必须重跑整套 `main()/vm_init()`
2. re-exec 之后很可能仍然需要：
   - 在新 `mm` 上重新建立 agent 区域映射
   - 刷新当前有效的 `_user_pt_regs`
   - 保证重新回用户态时 `sscratch/tp` 语义正确
3. `_do_irq` / `_excp_vect_table` / `_current_gp` 更像 Linux 内核侧静态锚点：
   - 它们属于 trap shim 的环境参数
   - 不是 same-PID re-exec 的主要变化源

当前设计倾向：

- `NACC_REEXEC` 不能复用 `nacc_invoke_child()`
- 也不应默认退化成“再次完整 agent 初始化”
- 更合理的目标是：
  - 保留独立 `REEXEC` 路径
  - 只做轻量 refresh
  - 不重新跑 `agent main`
  - 重点修复 `__agent_exit` / `__trap_entry` 相关的上下文接续

---

## 7. 调试约定（建议）

- 只保留“状态迁移级”日志，避免每 PTE 高频打印淹没关键信息。
- 每次实验记录三元组：
  - 命令（含完整 `docker run ...`）
  - 场景标签（如 `reexec_cat_only`）
  - 目标断言（如“无 second init”“child teardown 先 reclaim”）
