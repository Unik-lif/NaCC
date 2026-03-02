# NaCC Fork 支持分析与注意事项

## 背景

当容器中执行 `sh -c "cat"` 时，busybox 的 `sh` 会对 `cat`（非 shell builtin）执行 `fork() + execve()`。当前 NaCC 的页表替换机制未考虑 `fork()` 场景，这导致了 bug。本文分析 fork 与 NaCC 的交互点，以及未来支持 fork 需要注意的事项。

## fork 中页表相关的关键代码路径

```
fork() / clone()
  └─ copy_process()          [kernel/fork.c]
      ├─ copy_thread()        → 复制 thread_struct（包含 nacc_flag）
      └─ copy_mm()
          └─ dup_mm()
              ├─ mm_alloc_pgd()           → pgd_alloc() 分配新 PGD
              └─ dup_mmap()               → 遍历父进程所有 VMA
                  └─ copy_page_range()    [mm/memory.c:1399]
                      └─ copy_p4d_range()
                          └─ copy_pud_range()
                              └─ copy_pmd_range()   ← ★ PMD 级别
                                  └─ copy_pte_range()  ← ★ PTE 级别
```

## ⚠️ 需要注意的关键问题

### 问题 1：nacc_flag 被子进程继承

`fork()` 中 `copy_thread()` 会复制 `thread_struct`，因此子进程会继承 `nacc_flag`（包括 `NACC_INITED`、`NACC_RECLAIM` 等标志位）。

**影响**：
- 子进程的 `pmd_alloc()` / `pte_alloc()` 会走 SBI ecall 路径，从 NACC PTP 区间分配页表页
- 子进程 `execve` 时 `exit_mmap()` 释放旧 mm 会走 `NACC_RECLAIM` 路径
- 子进程退出时也会走 `NACC_RECLAIM` 释放路径

**需要确认**：这是否是期望的行为？如果不是，需要在 `copy_thread()` 或 `flush_thread()` 中清除/调整 `nacc_flag`。

---

### 问题 2：读取父 PTE 时直接走 new PTE 页

`copy_pte_range()` 中（[memory.c:1156](file:///home/link/NaCC/linux/mm/memory.c#L1156)）：

```c
src_pte = pte_offset_map_nolock(src_mm, src_pmd, addr, &src_ptl);
```

这个调用会走标准的 `pte_offset_map` 路径，它读取的是 **new PFN（NACC 替换后的）上的 PTE 条目**。

**问题**：new PTE 页上的条目可能包含 `_PAGE_NEW` 标记。如果 `copy_present_ptes()` 直接复制带有 `_PAGE_NEW` 的 PTE 到子进程的页表中，子进程的页表语义会被破坏。

**需要处理**：
- 复制 PTE 时，需要清除 `_PAGE_NEW` 标记，或者从 old PTE 页读取干净的 PTE 值
- 或者确认 `_PAGE_NEW` 标记在子进程中的含义是否仍然正确

---

### 问题 3：COW 写保护同步

`copy_present_ptes()` 对父进程的 PTE 设置写保护以启用 COW：

```c
// 大致逻辑：
ptep_set_wrprotect(src_mm, addr, src_pte);  // 父进程 PTE 去除写权限
set_pte_at(dst_mm, addr, dst_pte, pte);      // 子进程 PTE 也设置为只读
```

**问题**：`ptep_set_wrprotect` 修改的是 **new PTE 页上的条目**，但硬件实际使用（如果有 old PTE 页的话）的是 **old PTE 页**。如果 old PTE 页没有同步去除写权限，父进程写对应页面时 **不会触发 COW page fault**，导致父子进程直接共享同一物理页而不做复制。

> [!CAUTION]
> 这是最严重的正确性问题。COW 机制依赖于 PTE 写保护位，如果 old PTE 没有同步更新，会导致数据损坏。

**需要处理**：
- 对于有 old PTE 映射的情况，需要同步修改 old PTE 上的写保护位
- 或者在 fork 时通过 SBI 通知 monitor 同步这些修改

---

### 问题 4：子进程 PMD/PTE 分配路径

`copy_pmd_range()` 为子进程分配 PMD（[memory.c:1278](file:///home/link/NaCC/linux/mm/memory.c#L1278)）：

```c
dst_pmd = pmd_alloc(dst_mm, dst_pud, addr);
```

如果 `NACC_INITED` 被继承，这会走 SBI ecall 路径。

**需要确认**：
- Monitor 是否准备好为 fork 出的子进程分配新的 PTP 页？
- 子进程的 PGD 是通过标准 `pgd_alloc()` 分配的（不走 NaCC），那 PGD 后续是否也需要被 monitor 替换？
- NaCC PTP 区间的容量是否能支撑多个进程同时使用？

---

### 问题 5：ptlock 获取路径

`copy_pte_range()` 中获取源 PTE 锁：

```c
src_pte = pte_offset_map_nolock(src_mm, src_pmd, addr, &src_ptl);
spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING);
```

`pte_offset_map_nolock` 内部的 `pte_lockptr` 会通过 `pmd_page(*pmd)` 获取 struct page，再从中获取 ptlock。

**问题**：如果 src_pmd 指向的 PTE 页是 NACC PTP 页（new pfn），标准的 `pmd_page()` 返回的是 new pfn 对应的 struct page。但 `pagetable_pte_ctor` 可能是在 old pfn 或 new pfn 上做的，需要确保 ptlock 初始化在正确的 struct page 上。

---

### 问题 6：pmd_none_or_clear_bad 检查

`copy_pmd_range()` 中（[memory.c:1296](file:///home/link/NaCC/linux/mm/memory.c#L1296)）：

```c
if (pmd_none_or_clear_bad(src_pmd))
    continue;
```

如果 NaCC 替换过程导致某些 PMD entry 的标记位不标准，`pmd_bad()` 可能误判为 bad entry 而跳过复制。

---

## 可能的实现策略

### 策略 A：最小改动 —— fork 前暂停 NaCC

在 fork 执行前，将父进程的页表"回退"到标准状态（让 monitor 把 old PTE/PMD 页恢复回来），然后执行标准 fork 流程，fork 完成后再恢复 NaCC 状态。

- **优点**：改动最小，复用现有 fork 代码
- **缺点**：需要 SBI ecall 与 monitor 交互，性能开销较大；回退/恢复逻辑复杂

### 策略 B：fork 时使用 old PTE 作为源

修改 `copy_pte_range` 和 `copy_pmd_range`，当检测到 `NACC_INITED` 时，从 old PTE/PMD 页读取条目进行复制，并对 old PTE 页上的条目同步做 COW 写保护。

- **优点**：功能正确，不需要暂停 NaCC
- **缺点**：需要 NaCC-aware 版本的 `pte_offset_map`、`ptep_set_wrprotect` 等

### 策略 C：不继承 nacc_flag

Fork 时不让子进程继承 `NACC_INITED`，子进程使用标准 buddy 分配器分配页表页。仅在子进程 `execve` 时（如果需要保护）再重新设置 `nacc_flag` 并启动 NaCC 替换。

- **优点**：最简单，fork 路径完全不需修改
- **缺点**：fork 后、execve 前的短暂时间窗口内子进程没有 NaCC 保护；如果 fork 后不 execve（如纯 fork worker），则永远无法获得保护

### 策略 D：为 VM_NACC 区域跳过 COW 复制

对于 `VM_NACC` 标记的 VMA，在 `vma_needs_copy()` 中返回 false，让子进程通过 page fault 懒加载页面。

- **优点**：避免 fork 时遍历 NaCC 页表
- **缺点**：仅适用于 `VM_NACC` 区域，其他区域仍需正确处理

## 建议

> [!IMPORTANT]
> 综合考虑实现难度和正确性，**策略 C（不继承 nacc_flag）** 是最务实的起步方案。大多数容器场景中 fork 后都会紧跟 execve，短暂的无保护窗口可接受。后续再根据需要考虑策略 B 来完整支持长生命周期的 fork 子进程。

## 验证方案

验证 fork 支持是否正确的测试方法：

1. **基础测试**：`docker run busybox sh -c "cat"` —— 验证 fork + execve 不会 crash
2. **Fork-only 测试**：编写测试程序，fork 后子进程不 execve，直接访问内存，验证 COW 语义正确
3. **多级 fork 测试**：`docker run busybox sh -c "ls | grep foo"` —— 涉及管道，两次 fork + execve
4. **页表 debug**：在 fork 前后调用 `pgtbl_debug()` 对比父子进程页表状态

---

## 相关工作对比（2026-03-02 补充）

调研了两个类似的机密容器工作对 fork 的处理方式：

### BlackBox（OSDI'22，Columbia University）

- **机制**：使用 ARM nested page table（stage-2 页表）创建 PPAS（Protected Physical Address Space）
- **fork 处理**：OS 正常完成 fork，CSM（Container Security Monitor）**事后验证**
  - OS 调用 `task_clone` 通知 CSM
  - CSM 验证子进程页表内容和父进程一致
  - 将子进程的页表页加入 PPAS（修改 stage-2 映射）
- **性能**：fork 开销不到原来的 **3 倍**，主要来自地址空间验证
- **关键引用**：*"new page tables will be allocated for the child task and the CSM will ensure that they match those of the caller's and cannot be directly modified by the OS."*

### RContainer（NDSS'25，CAS / Boston University）

- **机制**：扩展 ARM CCA，使用 GPT（Granule Protection Table）保护内存
- **fork 处理**：类似 BlackBox，OS 正常 fork，Mini-OS 事后验证
  - 验证 task_struct 和地址空间完整性
  - 修改 GPT 标记子进程页表页为受保护
- **性能**：fork+exec 约 **10%** 额外开销

### 共同特点

两篇论文都**不在 fork 过程中做安全干预**，而是让 OS 正常完成 fork，事后由 monitor/CSM 验证并接管。BlackBox 用 stage-2 映射保护页表页，代价很低（改一条映射即可）；NaCC 用页表页替换机制，代价相对更高但可通过批量 SBI ecall 优化。

---

## 最终实施方案（2026-03-02 确定）

### 阶段 1：fork+exec 支持（最小改动）

**目标**：让 `sh -c "cat"` 等 fork+exec 场景跑通。

**改动**：在 `arch/riscv/kernel/process.c` 的 `copy_thread()` 中清除子进程的 `nacc_flag`：

```c
p->thread.nacc_flag = 0;  // fork 时切回 normal 状态
```

**原理**：
- fork 时子进程走标准 Linux 页表复制路径，零额外开销
- fork 产生的临时页表在 execve 时被 `exit_mmap()` 全部丢弃
- execve 加载新 ELF 时，现有的 NaCC 初始化逻辑（`nacc_invoke` 等）重新设置 `nacc_flag` 并启动页表替换

**性能开销**：零。

---

### 阶段 2：纯 fork 支持（Monitor 代劳方案）

**目标**：支持 fork 后不 exec 的子进程（如 nginx worker、daemon 子进程）也获得 NaCC 保护。

**核心思路**：对 VM_NACC 区域，跳过 Linux 的 `copy_pte_range` 逐级复制，改为一次 SBI ecall 让 monitor 完成页表复制。

**Linux 侧改动**（`copy_page_range` 或 `copy_pmd_range`）：

```c
if (src_vma->vm_flags & VM_NACC) {
    // 方案A：跳过 PTE 复制，不管 ref_count
    //         由 bitmap 保护兜底，代价是退出时多几次拦截检查
    // 方案B：轻量遍历 bump ref_count + 跳过 PTE 复制
    //         避免反复拦截的性能开销

    // 一次 SBI ecall 让 monitor 处理页表复制 + COW 设置
    sbi_ecall(SBI_EXT_NACC_FORK, parent_pgd, child_pgd, vma_start, vma_end, ...);
    child->thread.nacc_flag = NACC_INITED;
    return 0;
}
// 非 VM_NACC 区域：走标准 copy_pte_range
```

**Monitor 侧**：
1. 已知父进程的 old 页表（真实页表）的完整内容
2. 为子进程分配一套新的 NACC PTP 页
3. 复制父进程的页表结构到子进程
4. 在 old PTE 层面设置 COW 写保护（monitor 可直接操作）
5. 建立子进程的 nacc_mappings 映射关系

**ref_count 处理**：
- 数据页受 bitmap 保护，不会被 Linux 真正释放
- 可选择不维护 ref_count（方案 A），或轻量 bump（方案 B）
- 方案 A 的代价是进程退出时走释放路径被 bitmap 拦截（次数有限，可接受）

**性能开销**：一次 SBI ecall + monitor 端页表复制，远优于逐 PTE entry 的 ecall 方案。
