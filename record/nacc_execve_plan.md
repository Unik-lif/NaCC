# NaCC execve 支持计划

> 创建时间：2026-03-03

## 背景与问题定位

### 今日发现

通过分析 QEMU 日志，发现之前在 fork+exec 场景的推断方向有误：

- `sh -c "cat file"` **不会 fork**，busybox sh 直接对自身做 exec 优化（`execve(cat)`）
- `sh -c "echo a; echo b"` **不会 fork 也不会 execve**，echo 是 sh 内建命令
- 真正触发 fork 的写法：`sh -c "cat file; echo done"` 或管道 `echo x | cat`

### 当前 Crash 的根本原因

当同一进程进行第二次 `sys_execve`（即 sh → cat 这个过程）时，`begin_new_exec` 调用 `exit_mmap` 清理旧地址空间，`free_pgd_range → free_pgtables → kmem_cache_free` 试图释放系统已迁移到 NaCC 安全内存（`reserved` 区域）的页表页（PTP），导致内核 Oops。

```
epc : kmem_cache_free+0x8a/0x492
 ra : free_pgd_range+0x586/0xde2
Call Trace:
  free_pgd_range ← 试图释放 NaCC 安全内存中的 PTP
  free_pgtables
  exit_mmap     ← execve 中清理旧地址空间
  mmput
  begin_new_exec
  load_elf_binary
  sys_execve
```

---

## 实现计划

### Phase 0：execve 路径修复（当前紧急）

**目标**：在同一进程调用 `execve` 时，正确处理 NaCC 管理的 PTP 页，不让 `kmem_cache_free` 触碰这些页。

#### 0.1 分析 `exit_mmap` 的 PTP 释放路径

- [ ] 阅读 `exit_mmap → free_pgtables → free_pgd_range` 调用链
- [ ] 确认 NaCC PTP 页在 `pgd_free / pmd_free / pte_free` 哪个层次被错误释放
- [ ] 阅读 `pgalloc.h` 中现有的 `NACC_RECLAIM` 处理逻辑，确认是否覆盖了该路径

#### 0.2 修复 `free_pgd_range` 路径

可选方案：

**方案 A**：在 `pmd_free` / `pte_free` 钩子中检查 page 的 `reserved` 标志，若是 NaCC 页则跳过普通释放，改为调用 NaCC 自己的回收接口（类似 `sm_reclaim_ptp`）。

**方案 B**：在 `execve` 路径中，在 `begin_new_exec` 调用 `exit_mmap` **之前**，先调用一个 NaCC 专用的清理函数，将页表中的 NaCC PTP 替换回普通页或清零，使 `kmem_cache_free` 不再接触安全内存。

**推荐方案 B**，理由：
- 改动点集中，不需要在每个 `pmd_free` 中散落条件判断
- 与 `nacc_invoke` 的对称性更好（nacc_invoke 把页表迁入，execve 前把它迁出）
- 不影响非 NaCC 进程

#### 0.3 OpenSBI 侧接口

对应需要一个 `sm_restore_ptp(satp)` 或类似函数，把 NaCC 安全内存中搬移过的 PTP 页还原（或直接在 NaCC 内存中标记为已释放，并把页表指针清零），让 Linux 侧的 `exit_mmap` 可以安全跑完。

#### 0.4 验证

- [ ] 构建 Linux + OpenSBI
- [ ] 测试 `sh -c "cat /tmp/test.txt"` 不再 crash
- [ ] 确认 `sys_exit_group` 能正常完成，进程正常退出

---

### Phase 1：fork + exec 场景（execve 修复后）

**触发方式**：`sh -c "cat file; echo done"` 或 `docker run busybox sh -c 'cmd1; cmd2'`

**预期流程**：
1. sh fork 出子进程（`sys_clone`）
2. 子进程继承 `nacc_flag = NACC_FORKED`，NaCC 正确追踪子进程 PTP
3. 子进程 execve 加载目标程序（此时走 Phase 0 的 execve 修复路径）
4. `nacc_invoke_child` 被调用，子进程重新建立 NaCC 保护

**当前实现**（本次开发完成）：
- `copy_thread()` 中 `NACC_FORKED` 标记已实现
- `nacc_invoke_child()` Linux 侧已实现
- `sm_nacc_invoke_child()` OpenSBI 侧已实现（不跳转 agent，只做注册+PTP+映射）
- `thread_struct.nacc_cid` 已添加，用于子进程识别所属容器

**验证方式**：
- [ ] 测试 `sh -c "cat /tmp/test.txt; echo done"` —— 存在一次 fork
- [ ] 确认 SBI 日志中出现 `sm_nacc_invoke_child for pid` 打印

---

### Phase 2：纯 fork 场景（较复杂，暂缓）

**触发方式**：进程调用 `fork()` 后，子进程不 exec，两个进程共用同一 agent（待设计）

---

## 关键文件索引

| 文件 | 作用 |
|------|------|
| `linux/arch/riscv/mm/fault.c` | page fault 处理，含 `handle_page_fault` |
| `linux/arch/riscv/include/asm/pgalloc.h` | PTP 分配/释放钩子，含现有 `NACC_RECLAIM` 逻辑 |
| `linux/mm/memory.c` | `exit_mmap`, `free_pgtables` |
| `linux/mm/mmap.c` | `begin_new_exec` |
| `linux/arch/riscv/kernel/sys_riscv.c` | `nacc_invoke`, `nacc_invoke_child` |
| `linux/arch/riscv/kernel/process.c` | `copy_thread`，含 `NACC_FORKED` 标记 |
| `opensbi/lib/sbi/sm/sm.c` | `sm_nacc_invoke`, `sm_nacc_invoke_child` |
| `opensbi/lib/sbi/sm/cid.c` | NaCC 容器/进程管理 |
