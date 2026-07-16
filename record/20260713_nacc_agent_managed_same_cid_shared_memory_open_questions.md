# NaCC 同 CID 多进程共享问题说明

日期：2026-07-13

状态：问题记录，尚未形成设计结论，不代表当前代码已经支持目标语义。

本文只描述当前希望讨论清楚的问题、已有实现事实和约束，不提出具体实现
方案，也不预设最终应增加哪种硬件或软件机制。

## 1. 问题背景

NaCC 当前主要保护同一机密容器中各进程的普通用户数据页。默认语义是：

- 应用数据默认不共享；
- `fork` 后父子进程暂时映射同一物理页，是已有且语义明确的例外；
- fork 共享页通过只读映射、private refcount 和后续 COW 处理；
- 除 fork/COW 外，当前没有明确建立一套受保护的同 CID 多进程显式共享机制。

现在希望讨论的是：

> 如何让同一容器、同一 CID 下的多个进程显式共享一组内存页，并保持 Linux
> 无法读取、写入、复用或恶意重映射这些页面？

用户可见接口可能与 `mmap(MAP_SHARED)` 有关，但这里并不默认采用 POSIX shm、
tmpfs 或 Linux page cache，也不默认相信 Linux 对 VMA、PFN 和 object lifetime
的解释。

当前阶段不优先讨论通用跨 CID 共享，也不要求先解决每 PFN `ownerCID`。

## 2. 当前 bitmap 的原始含义

当前普通应用数据 PFN 仍然来自 Linux 管理的普通 RAM。OpenSBI 在页面对受保护
用户态可用以前，将需要保护的 PFN 标记为 `PRIVATE_DATA`。硬件访问检查随后
阻止 Linux S-mode 通过 user VA、direct map 或其他 alias 直接读取和写入该页。

这一机制原本要表达的是：

> Linux 已经把一个普通物理页交给机密应用以后，就不能再把该页当作自己可
> 自由读取、写入和复用的普通页。

当前 private refcount 主要对应 protected PTE mappings：

- 新建一个受保护 PTE mapping 时增加 reference；
- fork child 映射同一 PFN 时增加 reference；
- PTE 被清除、替换或回收时减少 reference；
- 当前实现中，最后一个 reference 消失后，PFN 可以退出 `PRIVATE_DATA` 状态。

因此，bitmap 和 private refcount 当前更接近“普通私有页的受保护映射生命周期”，
而不是通用 shared object 的所有权和生命周期记录。

## 3. 显式共享与现有 bitmap 语义的冲突

显式共享页与 fork/COW 页存在明显区别。

fork/COW 的共享关系来自已有地址空间的复制，父子 PTE、旧 PFN、新 PFN 和写
fault 的关系都比较明确。显式共享则需要额外回答：

- 哪个共享对象拥有这些页面；
- 哪些进程可以加入该共享关系；
- 同一对象在不同进程中可以映射到哪些 VA；
- 所有进程暂时 `munmap` 后，对象和数据是否仍应存在；
- 对象销毁和最后一个 PTE 消失是否是同一个事件；
- stale mapping 如何发现和撤销；
- 页面何时清零，何时允许重新分配；
- Linux 是否仍持有额外的 file、page-cache、shmem 或 allocator reference。

特别是，Linux shared object 可能在所有用户 PTE 消失后仍然保存 backing page。
若只依据当前 PTE refcount，在最后一个 mapping 消失时把 PFN 恢复为普通状态，
就可能出现以下窗口：

```text
protected PTE mappings become zero
        -> bitmap protection is removed
        -> Linux shared object still retains the backing page
        -> Linux can observe, reuse or remap the old data
```

因此，目前尚不清楚应当如何在不破坏 bitmap 原始含义的情况下表达显式共享。

## 4. 为什么不希望把共享完全交给 Linux

共享内存涉及大量 Linux 可控制状态，是典型的 Iago Attack 边界。恶意 Linux
可以操纵：

- `mmap` 返回的 VA；
- mapping 长度、offset、flags 和对齐；
- 与已有 VMA 的重叠关系；
- backing file 或 shmem object；
- page fault 时选择的 PFN；
- 是否建立额外 alias；
- `munmap`、`mremap`、fork、exec 和 exit 时的处理顺序；
- 是否保留 stale mapping 或额外内核 reference。

因此，即使最终保留 `mmap(MAP_SHARED)` 作为用户接口，也不能仅因为 Linux
创建了 `VM_SHARED` VMA 或安装了某个 PTE，就认为该共享关系是合法的。

希望讨论清楚的是：在 Linux 仍负责系统调用和 VMA compatibility 的情况下，
Agent/OpenSBI 至少必须掌握哪些事实，才能独立判断共享关系和页面生命周期。

## 5. 为什么会考虑由 Agent 管理共享页

当前的直觉是，显式共享不应继续使用 Linux 普通 shared-memory backing，原因
包括：

- 不希望 Linux 决定 shared PFN 的分配和复用；
- 不希望 shared object lifetime 隐藏在 tmpfs/page cache 等 Linux 对象中；
- 不希望把现有 bitmap 同时解释成 private mapping refcount 和 shared object
  lifetime；
- 希望共享是默认禁止下的显式例外，而不是普通 Linux mapping 的自然结果；
- Agent 已经承担受保护控制流、页表和内存操作中的可信部分。

由此产生了一个尚未解决的问题：如果共享页由 Agent 管理，它们与 Agent 自身
code、stack、allocator metadata 和安全控制状态之间应当是什么关系？

这里的“由 Agent 管理”至少可能包含以下不同含义，但目前尚未决定具体边界：

- 物理页来自 Agent 保留的内存；
- 页面生命周期由 Agent 记录；
- 映射关系由 Agent 检查；
- OpenSBI 根据 Agent 的可信请求更新安全页表；
- Linux 只保留兼容性 VMA 或系统调用外壳。

这些含义不一定要求 user app 能够访问整个 Agent region，也不自动说明 shared
pages 是否属于 Agent TCB。这个边界正是需要进一步讨论的内容。

## 6. 当前 Agent 隔离事实

当前固定 Agent physical aperture 为：

```text
base = 0x180000000
size = 0x20000000 (512 MiB)
end  = 0x1a0000000
```

该区域目前包含：

- Agent binary、BSS、stack 和 runtime allocator；
- semantic metadata；
- ordinary private PFN refcount arena；
- immutable system-page arena。

当前 Agent runtime 通过 supervisor PTE 映射到受保护 root，没有 `PTE_U`。
QEMU NaCC 访问检查还会拒绝 U-mode 访问受保护 Agent 范围，并根据
`nacc_state` 区分 Agent S-mode 与 Linux S-mode。

需要注意当前实现中有三个名称相近但含义不同的边界：

- linker symbol `eagent`：Agent image/runtime footprint 的结束位置；
- CSR `nacc_eagent`：NaCC 硬件模型使用的 Agent protected-range end；
- 固定 physical aperture end：Agent base 加 512 MiB。

如果共享页位于 Agent 保留内存中，就必须重新说明 user app、Linux、Agent 和
OpenSBI 对不同 Agent-owned pages 的访问权限。当前统一的 Agent-range 检查并不
直接表达“Agent private pages”和“用户可访问的 Agent-managed pages”两种类别。

## 7. 硬件表达上的困难

希望讨论的逻辑权限关系大致是：

| 访问主体 | Agent 私有控制状态 | Agent 管理的共享数据 |
|---|---:|---:|
| 同 CID user app | 不应访问 | 需要访问 |
| Linux S-mode | 不应访问 | 不应访问 |
| Agent S-mode | 需要访问 | 需要管理或访问 |
| M-mode/OpenSBI | 需要访问 | 需要管理或访问 |

标准 PMP 通常为 S/U 提供共同的物理访问权限，不能直接表达“允许 U-mode、拒绝
Linux S-mode”。当前 NaCC 已经通过 `nacc_state` 和额外 physical-access check
区分 Agent S-mode 与 Linux S-mode，但尚未明确如何在不显著增加硬件状态的
情况下，再区分 Agent private pages 与 Agent-managed shared pages。

这个问题至少涉及以下约束：

- 可以对 NaCC 自定义硬件检查作有限修改；
- 不希望修改标准 PMP 的语义；
- 不希望增加大量 CSR，使硬件故事和上下文同步变复杂；
- 当前 `sagent/eagent` 已经承担 Agent range 相关含义；
- 不希望隐式引入多个难以解释的 end/boundary；
- 如果完全依赖安全页表，则必须说明 Linux 是否可能预植 PTE、请求恶意 PTE
  update、切换 SATP 或利用 stale TLB；
- 如果依赖物理地址分类，则必须说明地址范围、粒度、初始化和多 hart 同步；
- 如果依赖 per-page metadata，则必须说明它与现有 bitmap 的关系；
- 还需要考虑 instruction fetch、TLB permission caching 和 DMA 是否属于威胁
  模型。

目前尚未确定应由哪一层承担 Agent-private 与 Agent-managed-shared 的最终区分。

## 8. rContainer 能提供什么参照

RContainer 的 mini-OS 与 deprivileged OS 运行在同一异常级，但通过不同 GPT
视图隔离。其论文中的 Shim-GPT 权限表表明：

- self container 和 self con-shim 可以访问自己的内存；
- container/con-shim 不能访问 mini-OS；
- deprivileged OS 不能访问 mini-OS 和 container private memory；
- mini-OS 作为 reference monitor 管理 container/con-shim memory；
- con-shim 属于 container data plane，并不属于 mini-OS TCB。

RContainer 还由 mini-OS 管理预留物理内存池，并记录页面权限、所属 container
和映射次数。对于 page fault、`mmap` 和 IPC shared memory，mini-OS 会检查
VA/PFN 和目标 mapping，而不是直接相信 deprivileged OS。

官方资料：

- https://www.ndss-symposium.org/ndss-paper/rcontainer-a-secure-container-architecture-through-extending-arm-cca-hardware-primitives/
- https://www.ndss-symposium.org/wp-content/uploads/2025-328-paper.pdf

但 rContainer 不能直接给出 NaCC 的答案：

- rContainer 依赖 ARM CCA GPT/GPC；NaCC 当前没有等价的 per-container GPT；
- rContainer 的 con-shim 包含 kernel-layer data plane，不完全等价于 NaCC Agent；
- rContainer 用于 syscall 参数传递的 shared buffer 可以对 deprivileged OS 可见，
  而 NaCC 当前讨论的是 Linux 不可见的同 CID 进程共享；
- NaCC 希望避免显著扩展 PMP 或增加大量硬件寄存器。

因此，希望借助 rContainer 澄清的是信任边界是否合理，而不是照搬它的硬件
实现：Agent private/control 与 user-visible shared data 是否应当保持不对称
隔离，以及 shared data 是否可以被描述成 Agent 管理但不属于 Agent TCB 的
container data plane。

## 9. 共享对象还缺少的语义定义

即使先不决定硬件实现，以下语义仍需要明确：

1. 什么操作创建一个合法共享对象？
2. 共享对象如何被同 CID 的第二个进程识别？
3. Linux 提供的 handle、FD、VA 和 VMA 中，哪些只是非可信输入？
4. Agent/OpenSBI 需要保存哪些 root、VA、PFN 和权限信息？
5. 所有用户 mapping 消失后，对象是否继续存活？
6. object destroy 与最后一个 PTE removal 的关系是什么？
7. 如何发现并清除 Linux 隐瞒的 stale mapping？
8. 页面重新分配以前由谁清零？
9. object identifier 被复用时，如何防止旧 handle 访问新对象？
10. 已存在的共享 mapping 在 fork 后是否自动继承？
11. exec、exit 和异常终止时，谁负责撤销 mapping 和回收对象？
12. 同 CID 是否意味着所有进程互相信任，还是仍需要 object-level admission？

这些问题不能仅由现有 bitmap refcount 回答，因为一个计数值不能指出具体哪些
root/VA 正在引用页面，也不能单独表示 object 是否仍然存在。

## 10. 希望外部讨论回答的问题

1. 在 Linux 恶意、Agent/OpenSBI 可信、当前只考虑同 CID 多进程的条件下，
   “默认不共享，fork 是已有例外，其他共享必须显式授权”是否是足够清楚的
   安全语义？
2. 由 Agent 管理 shared physical pages，是否比复用 Linux shmem/page cache
   更符合这一威胁模型？需要付出哪些兼容性和可用性代价？
3. 参考 rContainer，Agent private/control 是否仍应当与 user app 隔离？
   “Agent-managed but outside Agent TCB”的 shared data plane 是否合理？
4. 在不修改 PMP 语义、尽量不增加 CSR 的情况下，目标权限关系至少需要哪些
   可信硬件状态和软件状态？
5. 为了使该权限关系不可绕过，页表、SATP、TLB 和多 hart 切换分别需要满足
   哪些 invariants？
6. 应如何划分现有 `nacc_state`、Agent range check、secure page table、bitmap
   和 Agent metadata 的职责，才能避免同一安全事实被多套机制重复表达？
7. 如何保留 `mmap(MAP_SHARED)` 形式的用户接口，同时抵抗 Linux 操纵 VA、PFN、
   VMA、fault 和 object lifetime 的 Iago Attack？
8. 是否可以在当前阶段只使用 object-level CID/root authorization，而不引入
   per-PFN ownerCID？这种简化的安全边界是什么？
9. shared object 的存活、mapping 和物理页回收应分别由什么事件驱动？
10. 应如何描述这一机制，才能避免让读者误以为 NaCC 已经支持完整 POSIX shm、
    通用 Linux `MAP_SHARED` 或 per-container GPT？

## 11. 可直接转发的简短问题描述

NaCC 是一个 RISC-V 机密容器原型。Linux 被视为不可信；OpenSBI Monitor 和
一个由 `nacc_state` 与 Linux 区分的 S-mode Agent 属于 TCB。普通应用数据页
来自 Linux RAM，在对受保护用户态可见前由 Monitor 设置 PFN bitmap，阻止
Linux 后续直接访问或复用。private refcount 当前主要跟踪 protected PTE
mappings，fork/COW 是已有且语义明确的共享例外。

现在希望支持同一 CID 下多个进程的显式 `mmap(MAP_SHARED)`，但不希望使用
POSIX shm、tmpfs/page cache 或让 Linux 决定 PFN、VA 和 object lifetime。原因
是 Linux 可以通过 mmap/fault/unmap 等路径实施 Iago Attack，而且 shared
object 可以在所有 PTE 消失后继续持有 backing page，使现有 bitmap/refcount
语义失效。

当前考虑让 Agent 管理 shared pages，但尚未想清楚两件事。第一，Agent private
code/data/control metadata 是否必须继续与 user app 隔离；rContainer 的做法是
container/con-shim 不能访问 mini-OS，而 mini-OS 可以管理 container data。
第二，如果 shared pages 来自 Agent 保留内存，如何表达“user app 可访问 shared
data、Linux 不可访问、user app 又不能访问 Agent private data”的权限关系。
标准 PMP 不直接区分 Linux S-mode 与 U-mode，而项目又希望避免修改 PMP 语义或
增加大量 CSR。

请帮助分析这一问题的信任边界和最小安全机制，特别是 Agent/user 隔离是否
必要、shared object lifetime 应如何区别于 PTE refcount，以及如何在保留
`mmap(MAP_SHARED)` 用户语义的同时抵抗恶意 Linux。请不要默认采用完整 POSIX
shm、per-container GPT 或大量新增硬件寄存器。
