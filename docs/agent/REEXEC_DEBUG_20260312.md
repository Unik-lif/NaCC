# NaCC same-PID re-exec 调试资产（截至 2026-03-12）

> 目的：沉淀这轮 `same-PID re-exec` 的关键收敛结论，避免后续再次从旧假设起步。

## 1. 复现场景

本轮主要围绕以下命令分析：

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /tmp/test.txt"
```

它是当前最稳定的 same-PID `re-exec` 最小复现。

含义：

- `busybox sh -c ...` 先进入 shell
- 随后 `cat` 往往触发同 PID `re-exec`
- 因此适合观察 `INITED -> REEXEC -> INITED/RECLAIM` 的真实行为

## 2. 这轮调试中已经排除掉的旧问题

### 2.1 不是 logger 混入旧 pane 历史

已修正 `make logger` 的 pane 选择和 run marker 截取逻辑。  
新日志能够干净捕获当前一次实验，不再把更早的 `cat /etc/hostname` 或其他旧命令混进来。

### 2.2 不是 “reexec 后仍访问旧 agent VA”

早期日志里，`reexec` 后仍访问旧 agent 基址 `0x2aaaaab000 + 0x68`，这是明显错误。

后续修复后，`invoke` 和 `reexec` 都稳定使用当前 agent 基址，例如：

- `virt_agent = 0x3ec0000000`

因此：

- “旧 agent VA 残留” 已不是主问题

### 2.3 不是 “same-PID reexec 可以继续复用 fork child 语义”

这个设计假设已经被证伪。

same-PID `re-exec` 不能再被当成：

- `fork child re-attach`
- 或 `nacc_invoke_child()` 的同 PID 版本

原因：

- PID 没变，但 `exec` 后用户映像与 `mm` 已变化
- trap/runtime 前提也变了
- 继续复用 `fork child` 语义，会导致上下文和页表页 metadata 混淆

## 3. 关键收敛过程

### 3.1 第一阶段结论：`Bad page state` 不是最早首因

较早阶段日志里，最醒目的报错是：

- `BUG: Bad page state in process ... pfn:...`

但后续分析发现：

- 它更多反映 Linux 侧 `struct page` / `ptdesc` / ptlock 元数据不一致
- 不足以单独解释第一次 `cat` 为什么立刻崩溃

当时真正更像首因的是：

- Linux trap entry 中 `tp/sscratch` 语义错位

这一步的重要价值是：

- 帮我们把注意力从“单纯 metadata 脏页”移开
- 转向 `reexec` handoff 语义是否正确

### 3.2 第二阶段结论：第一 trap 确实先到了 agent

从日志中的：

- `Agent will jump to twin_entry!`

以及 GDB 观察可确认：

- 用户态第一波 trap 并没有直接绕过 agent 进入 Linux
- 硬件路径仍是：`user -> agent __trap_entry -> 再决定是否交给 Linux`

这一步的重要价值是：

- 排除了“twin-entry 失效”
- 把范围收缩到 agent 自身 trap 保存路径

### 3.3 第三阶段结论：真正首因在 agent `__trap_entry`

这轮最重要的收获来自 GDB：

- 崩溃点不在 Linux
- 也不在 `__agent_exit` 之后
- 而是在 agent `__trap_entry` 保存 trap frame 的早期阶段

具体位置：

- `agent/src/entry.S`
- `sd x1, PT_RA(sp)`

这说明：

1. reexec 后的第一次间歇性 timer trap 已经进入 agent
2. agent 准备把 trap 上下文保存到自己的 `_user_context`
3. 但对这块内存的第一次写入就 fault 了

因此 Linux 侧随后看到的：

- `do_page_fault`
- `_new_vmalloc_restore_context_a0`
- 甚至后续 Oops

本质上是 agent 自己这次 page fault 的后续连锁效应，不是首因。

## 4. 当前最可信的根因

当前最强假设是：

- `_user_context` 所在页属于首次 invoke 时动态分配并显式映射的 runtime page
- 但 `reexec` 新 `mm` 只重新映射了 agent image 基础区间
- 没有把 `_user_context` 这类 runtime page 一起重新映射
- 所以第一波 trap 一写 `_user_context` 就 page fault

对应代码链如下：

- `trap_init()` in `agent/src/trap.c`
  - 通过 `explicit_kalloc()` 分配 `_user_context`
- `explicit_kalloc()` in `agent/src/mem.c`
  - 分配后通过 `sbi_ecall_agent_mmap()` 显式映射到 Linux 当前页表
- `vm_init()` in `agent/src/vm.c`
  - 只负责 agent image 基础映射
- `sm_nacc_reexec()` in `opensbi/lib/sbi/sm/sm.c`
  - 当前 reexec 也只 remap 了基础 image 区间

因此根因不是：

- “agent 没有进入”
- “Linux trap 入口先坏”
- “旧 agent VA 残留”

而是：

- **reexec 后 agent 自己的 trap save page 没准备好**

## 5. 当前状态评估

截至 2026-03-12 最新一轮日志，状态已经明显变好：

- `reexec` 主路径已经能走通
- VM 侧命令能够正常返回用户可见结果
- 不再出现之前那种立刻 panic / kernel stack overflow / `Attempted to kill init`

但系统仍未完全干净。

最新日志中仍可见：

- `BUG: Bad page state in process systemd-journal  pfn:1bfff5`

这说明：

- `same-PID reexec` 的主路径已显著改善
- 但页表页 metadata / reclaim / transfer 仍有尾部一致性问题

当前更准确的说法是：

- **reexec 已从“直接失败”推进到“基本成功，但仍带一个 `Bad page state` 尾巴”**

## 6. 设计层面的新结论

### 6.1 既然 agent VA/PA 已固定，reexec 逻辑应继续收敛

既然当前 agent 物理地址和虚拟地址都已经固定，很多围绕“地址会变化”写出来的逻辑应重新审视。

重点怀疑对象：

- `__reexec_entry` 中对 `_user_context` 的 rebasing
- `__reexec_entry` 中对 `kmem.freelist` 的调整
- `_offset` 在 reexec 中的重新计算和重新使用

如果这些逻辑建立在旧前提上：

- “每次 reexec agent VA 可能变化”

那现在很可能已经变成冗余，甚至会继续制造错乱。

### 6.2 trap save page 更适合固定化，而不是运行时显式补映射

当前更推荐的长期方向是：

- 不再让 `_user_context` 依赖 `explicit_kalloc()`
- 直接在 agent image / `.bss` / `.sbss` 中预留固定 trap context 页
- 让 `__trap_entry` 只依赖 agent 固定映射区内的数据

好处：

1. `reexec` 只需要 remap 基础 image
2. 不再维护额外 runtime page remap
3. 可以删除一批 rebase / 补映射 / 动态页依赖逻辑

## 7. GDB 调试资产

### 7.1 agent ELF section 与运行地址映射

当前 agent ELF 不是单一 `.text`，而是分段布局。

典型运行时对应关系：

- `.entry.text -> 0x3ec0000000`
- `.reexec     -> 0x3ec0001000`
- `.text       -> 0x3ec0002000`

因此不能简单使用：

```gdb
add-symbol-file agent.elf 0x3ec0000000
```

也不能只给 `.text` 一个地址。

更可靠的写法是按 section 显式加载。

### 7.2 推荐断点

优先观察：

- `__reexec_entry`
- `__trap_entry`
- `__agent_exit`

在当前场景下，优先使用 `hbreak` 而不是普通 `break`。

原因：

- `hbreak` 不需要修改目标内存
- 跨 `mret`、特权级切换、guest 映射变化时更可靠

## 8. 当前最值得继续做的事

1. 先验证 `_user_context` 实际地址是否落在 reexec remap 区间之外
2. 若是，优先修复 `_user_context` / trap save page 的可达性问题
3. 随后单独清理 `Bad page state` 对应的页表页 metadata 生命周期
4. 继续删减建立在“agent VA 会变化”前提上的 rebase 逻辑

## 9. 一句话总结

这轮 same-PID `reexec` 调试的最大收获是：

- **首因已经从“大而模糊的 Linux Oops”收缩成 agent `__trap_entry` 对 `_user_context` 的第一次写入 fault；**
- **reexec 主路径已经基本跑通；**
- **剩余问题主要集中在 trap save page 固定化和页表页 metadata 尾部一致性。**
