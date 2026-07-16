# NaCC Agent 预留内存与 bitmap 保护的同 CID mmap shared 实现方案

日期：2026-07-13

状态：下一步实现方案草案。本文给出当前建议采用的首版边界和实施顺序，
不代表代码已经支持该功能，也不代表已经解决跨 CID 共享、恶意 DMA 或完整
POSIX shared-memory 兼容。

> 2026-07-14 更新：本文保留物理布局、bitmap tag、shared pool 与 ordinary
> refcount 分离等底层分析。关于对象 authority、用户调用路径、Linux VMA 参与
> 程度和 last-mapping 生命周期的最新基线，改以
> `20260714_nacc_agent_direct_shared_memory_design_baseline.md` 为准。后者取代本文
> 中“Linux 参与每个 shared mmap/unmap”和“由 OpenSBI 保存完整 shared-object
> policy metadata”的旧草案结论。

## 1. 本轮结论

继续使用 PFN bitmap 保护 Agent-managed shared memory 是合适的，但必须限制
bitmap 的职责：

> bitmap 只回答“当前这个 PFN 属于哪一种物理访问类别”；它不回答“哪个共享
> 对象拥有该页、哪些进程可以映射、对象是否仍存活”。

首版采用“前置 shared pool，后置 Agent private region”的固定划分：

1. `[0x180000000, 0x190000000)` 暂定为 256 MiB Agent-managed shared pool；
   这是原 512 MiB Agent 预留区的前半段。
2. `nacc_sagent` 和 Agent image 起点上移到 `0x190000000`；后半段继续由现有
   `nacc_sagent/nacc_eagent` base-and-bound 保护 Agent code、heap 和 control
   metadata。
3. bitmap coverage 延伸到新的 `sagent`，因此只覆盖前置 shared pool，不覆盖
   后续 Agent-private PFN。两种硬件机制在物理地址上不重叠，不需要在 Agent
   base-and-bound 内为 U-mode 增加 shared 例外。
4. shared pool 中的 live page 复用 `PRIVATE_DATA`；空闲和回收中的 page 复用
   M-mode-only 的 `PRIVATE_COPY_PENDING` 编码，作为 shared-reserved/PEND 状态。
   不增加 bitmap 位宽，也不新增 CSR。
5. OpenSBI 保存 shared object、CID、generation、page list 和 root/VA mapping
   记录；同 CID 授权和生命周期不能由 bitmap 单独表达。
6. Linux 的 `mmap(MAP_SHARED)` 只作为 VMA/VA compatibility 外壳。Linux 提供
   的 VA、长度、offset、flags、handle 和 fault 事件全部是不可信输入，不能让
   Linux 选择 shared PFN。

这一分工保留了当前 bitmap “最终物理访问检查”的优点，也避免把一个 2-bit
状态错误扩展成 shared-object authority。256 MiB 只是原型默认值，安全边界是
`shared_end == nacc_sagent`，而不是这一具体容量。

## 2. 当前实现事实

当前 5 GiB 物理布局中：

```text
0x80200000 - 0x180000000    Linux/普通应用 RAM，当前 bitmap 跟踪范围

0x180000000                Agent physical aperture 起点
0x180000000 - 0x18003a000  当前 Agent image/runtime footprint（232 KiB）
0x18003a000 - 0x19faf0000  当前 Agent page allocator 可用范围
0x19faf0000 - 0x19fb00000  semantic table（64 KiB）
0x19fb00000 - 0x19ff00000  ordinary PRIVATE_DATA refcount（4 MiB）
0x19ff00000 - 0x1a0000000  immutable VDSO arena（1 MiB）

0x1a0000000 - 0x1a0040000  PFN tag bitmap（当前 256 KiB）
0x1a0040000 - 0x1b0000000  OpenSBI pvt_mem pool
0x1b0000000 - 0x1c0000000  secure PTP/sec_mem pool
```

本轮已经完成的 bitmap 加强包括：

- tag 检查不再只对当前 NaCC/Linux 状态下的特定访问生效；普通 U-mode 也不能
  被 Linux 用作绕过 PRIVATE_DATA 防护的代理；
- QEMU 在 tag 变化后按 PFN 定向失效全部 vCPU/MMUIdx 中的对应 TLB alias 和
  code TB，不做全局 TLB flush；
- bitmap metadata 仍位于原物理地址，OpenSBI 的 2-bit 编码未改变。

这些修改使 bitmap 可以继续作为 shared page 的底层物理访问状态。当前常量把
“整块 512 MiB 预留区起点”“Agent image 起点”“PMP Agent region 起点”和
`nacc_sagent` 混成了同一个 `SBI_DOMAIN_AGENT_REGION_BASE`；实现前必须拆开这些
语义，而不能只改一个数字。

## 3. 建议的首版物理划分

共享池放在原 Agent 预留区的前端，真正的 Agent private region 随后开始：

```text
NACC_RESERVED_REGION_BASE       = 0x180000000
NACC_SHARED_REGION_BASE         = 0x180000000
NACC_SHARED_REGION_SIZE         = 0x10000000       /* 256 MiB */
NACC_SHARED_REGION_END          = 0x190000000

SBI_DOMAIN_AGENT_REGION_BASE    = 0x190000000       /* new nacc_sagent */
SBI_DOMAIN_AGENT_REGION_SIZE    = 0x10000000
NACC_AGENT_PROTECTED_REGION_END = 0x19ff00000       /* nacc_eagent */
NACC_RESERVED_REGION_END        = 0x1a0000000
```

对应布局变成：

```text
0x180000000 - 0x190000000  Agent-managed shared-data pool，256 MiB
0x190000000 - 0x19003a000  relocated Agent image/runtime footprint（预计 232 KiB）
0x19003a000 - 0x19faf0000  Agent-private allocator，预计约 250.71 MiB
0x19faf0000 - 0x19fb00000  semantic table
0x19fb00000 - 0x19ff00000  ordinary private refcount
0x19ff00000 - 0x1a0000000  immutable VDSO arena
```

这里的 `0x19003a000` 是按当前 linker footprint `0x3a000` 平移得到的预计值；
Agent linker symbol `eagent` 仍应由实际链接结果产生，不能硬编码。它也不同于
CSR `nacc_eagent=0x19ff00000`，文档和代码命名需要避免继续混淆这两个边界。

该布局有三个直接好处：

- shared pool 完全位于 `[nacc_sagent,nacc_eagent)` 之外，由 bitmap 决定最终
  物理访问权限；
- Agent code/heap/control metadata 完全位于 base-and-bound 内，维持当前所有
  U-mode 和 Linux S-mode deny，不需要 shared 特例；
- shared pool 的末端就是 bitmap coverage 的末端和新的 `sagent`，不需要新增
  shared base/end CSR。`0x180000000` 可以作为构建期固定 shared base。

Agent 的 `mem_init()` 只管理 relocated linker `eagent` 到
`NACC_AGENT_RUNTIME_REGION_END`。shared pool 使用独立 allocator 和 descriptor，
不能与 Agent stack、page-table scratch、控制 metadata 或普通 Agent heap 混用。

### 3.1 PMP 与 Linux 预留边界

现有 root-domain Agent PMP region 也必须从新的 Agent base 开始，不能继续覆盖
前置 shared pool。它可以保持 `[0x190000000,0x1a0000000)` 的 256 MiB region，
其中更窄的 semantic/refcount/immutable entries 继续按现有优先级处理。首次
invoke 只打开该 Agent-private PMP region；shared pool 的安全性由 PFN tag 保证。

Linux 仍需在启动时把 shared、Agent、metadata 和 secure PTP 的整段物理内存从
buddy 中功能性预留。当前 Makefile 的 legacy 参数是
`memmap=1025M$0x17ff00000`；布局迁移时应改成语义相同且边界准确的
`memmap=1024M$0x180000000`。这项预留只避免正常 Linux allocator 使用该范围，
不能作为抵抗恶意 Linux 的安全依据。写入 Makefile recipe 时，`$` 仍需按现有
形式转义，因此源码拼写应为 `memmap=1024M\$$0x180000000`。

## 4. bitmap 在 shared pool 中的语义

首版不新增 tag，继续使用现有四种值：

| tag | ordinary RAM 中的含义 | shared pool 中的含义 |
|---|---|---|
| `NORMAL` | Linux 普通页 | 非法/尚未初始化；不能作为稳态 free shared frame |
| `ROOT_L0` | protected root page | shared pool 中禁止使用 |
| `PRIVATE_DATA` | active confidential user data | active Agent-managed shared data |
| `PRIVATE_COPY_PENDING` | 可信复制/提交过渡页 | free/reserved shared frame，以及初始化、销毁和清零期间的 M-mode-only quarantine |

这里应把 `PRIVATE_DATA` 理解为“protected confidential data”，而不是“只能被一个
进程映射”。同一 PFN 是否允许多 root 映射，由 shared object metadata 决定。

启动时，OpenSBI 应在 Linux 运行前把整个 shared pool 初始化为
`PRIVATE_COPY_PENDING` 并完成可信清零。对 shared PFN 而言，该编码可以在
OpenSBI 内部命名为 `SHARED_RESERVED/PEND`，但线上 2-bit 值仍为 3。这样空闲页
也不能被恶意 Linux 预写、读取或建立 stale alias；Agent 只管理 allocator
metadata，实际读写和清零通过受控 ecall 进入 M-mode。

shared page 的稳态转换是：

```text
boot:       NORMAL -> PEND -> trusted zero -> free(PEND)
allocate:   free(PEND) -> trusted zero -> install descriptors -> PRIVATE_DATA
destroy:    revoke PTEs -> PRIVATE_DATA -> PEND -> trusted zero -> free(PEND)
```

销毁后不回到 `NORMAL`。如果临时实现选择让 free frame 保持 `NORMAL`，则恶意
Linux 在分配前仍能写入该页；分配时先转 PEND 并可信清零可以保护后续数据的
机密性和完整性，但不能再宣称整个 shared reserve 始终不可被 Linux 触碰。该
较弱语义不作为本文首版目标。

bitmap coverage 变为：

```text
[0x80200000, 0x190000000)
```

其中新增的最后 256 MiB 恰好是 shared pool；新的 Agent-private region 不在
bitmap 内。按该范围计算，tag bytes 为 `0x43f80`，页对齐后的 metadata size
为 `0x44000`，因此 `pvt_mem.start` 从 `0x1a0040000` 移到
`0x1a0044000`。OpenSBI 与 QEMU 必须由同一组 coverage 常量计算这些值，不能
各自硬编码。

### 4.1 不直接扩展现有 ordinary private refcount

当前 4 MiB ordinary private refcount arena 几乎恰好覆盖：

```text
[0x80200000, 0x180000000)
```

该 ordinary range 需要 `0x3ff800` bytes，只剩 `0x800` bytes。若把 refcount
也扩展到新的 bitmap end，所需空间会变成 `0x43f800` bytes，现有 arena 会
立即越界。首版必须拆开：

- tag bitmap 的 PFN coverage 扩展到 shared pool；
- ordinary private refcount coverage 仍截止 `0x180000000`；
- shared PFN 的 object/map reference 保存在独立 shared-page descriptor 中。

这也避免继续把 ordinary PTE reference 和 shared object lifetime 混成同一个
计数。

## 5. 最终物理访问策略

当前 QEMU 检查顺序是 PMP、PFN tag、Agent base/bound。采用前置 shared pool
以后，tag 和 base-and-bound 分别覆盖不相交的范围，不再需要组合放行：

| 访问主体 | Agent private `[sagent,eagent)` | shared free/reserved `PEND` | shared live `PRIVATE_DATA` |
|---|---:|---:|---:|
| ordinary U-mode | base/bound deny | bitmap deny | bitmap deny |
| protected U-mode | base/bound deny | bitmap deny | allow according to trusted PTE R/W |
| Linux/INACTIVE S-mode | base/bound deny | bitmap deny | bitmap deny |
| Agent S-mode | allow | bitmap deny；通过受控 ecall 交给 M-mode | allow |
| M-mode/OpenSBI | allow | allow | allow |

具体 invariant 是：

1. `[0x190000000,0x19ff00000)` 维持当前 U/Linux deny；该范围不需要 bitmap
   tag，也不存在任何 shared U-mode 例外。
2. `[0x180000000,0x190000000)` 中除 `PEND` 和 `PRIVATE_DATA` 外不允许出现稳态
   tag。protected U-mode 只有在 `PRIVATE_DATA` 且 trusted mapping record/PTE
   均有效时才能访问；普通 U 和 Linux S 始终 deny。
3. shared pool 首版只建立 U+R/W+!X leaf。所有 typed map、通用 PTE update、
   attach sweep 和 fork 路径都必须拒绝 `PTE_X`；可以再在 final-PA check 中按
   shared range 拒绝 instruction fetch，作为不依赖 PTE 的纵深检查。
4. `PRIVATE_COPY_PENDING` 对所有非 M-mode 访问 fail-closed。初始化或销毁若需
   Agent 协助，应通过受控 ecall，而不是让 Agent 并发直接访问 PEND page。
5. bitmap deny 对所有 hart 和所有 NaCC state 生效；不能重新退化为“仅当前
   protected process 生效”。`PRIVATE_DATA` 的 allow 集仍是 M-mode、Agent-state
   S-mode 和 Agent-state protected U-mode。

该规则不需要改变标准 PMP 语义，也不需要新增 CSR。现有 `nacc_sagent` 的值从
`0x180000000` 改成 `0x190000000` 即可表达新的硬件边界；shared base 保持平台
固定常量，bitmap end 与 `sagent` 必须由构建期断言证明相等。

还需要注意，当前 QEMU 的 PMP check 位于 tag/base-bound check 之前。现有首次
invoke 会调用 `clear_pmp_and_sync(agent_pmp_region)`，随后依赖 NaCC base/bound
继续隔离 Agent。迁移后 `agent_pmp_region` 必须只指向后置 Agent region；shared
pool 不得被该 M-only PMP entry 覆盖，否则合法 protected U mapping 会在 bitmap
以前被 PMP 拒绝。所有 hart 上的 PMP entry 与 `sagent/eagent` CSR 值必须一致。

## 6. bitmap 不能替代的 trusted metadata

OpenSBI 至少需要维护以下逻辑对象：

```text
shared_object:
    object_id
    generation
    cid
    state                 CREATING / LIVE / DESTROYING
    size / page_count
    page_list
    handle_refs
    mapping_refs

shared_mapping:
    object_id + generation
    root_pfn
    pid（用于清理和诊断）
    user_va
    length / object_offset
    allowed_prot

shared_page:
    pfn
    object_id + generation
    mapping_refs
    lifecycle state
```

关键点如下：

- object lifetime 与 PTE mapping count 必须分开；
- 最后一个 mapping 消失时，对象可以继续存活，page 必须继续受保护；
- 只有 object destroy/最后一个 handle 释放才能启动 page reclaim；
- `generation` 防止旧 handle 在 object id 复用后指向新对象；
- 每次 PTE install/remove 都要更新具体 root/VA mapping record，不能只有一个
  总 refcount；
- 首版只要求 object 的 `cid`，不要求通用 per-PFN ownerCID。每个 shared page
  通过 object descriptor 间接归属于一个 CID。

如果将来需要同 CID 内部的进程级隔离，可以在 object 上增加 member/ACL；首版
可以把同 CID 进程视为同一互信域，但仍要求有效的 object id/generation。

## 7. mmap shared 的首版协议

首版可以保留 `mmap(MAP_SHARED)` 的用户接口形状，但不采用 POSIX shm、tmpfs、
page cache 或 Linux file-backed PFN。

`MAP_SHARED` flag 本身不能让两个非 fork 进程识别同一个 object。首版仍需要
Agent/runtime ABI，例如：

```text
nacc_shared_create(size, flags) -> object_id + generation
nacc_shared_map(object_handle, addr_hint, prot) -> mmap-style user VA
nacc_shared_unmap(object_handle, user_va)
nacc_shared_close(object_handle)
```

这里的 handle 由 Agent/OpenSBI object table 解释，不是 Linux file、inode 或
page-cache object。Linux 可以转发和保存 handle，但不能仅凭 handle 自行选择
PFN 或提交 PTE。首版把同 CID 视为互信域；跨进程 handle 如何传递可以由应用
协议或容器 runtime 决定。

### 7.1 Linux 只负责 compatibility shell

Linux 可以负责：

- 选择候选 VA；
- 建立带 NaCC shared 标记的 VMA；
- 保存不可信 object handle，供 fault/unmap/exit 路由；
- 维护用户可见的 mmap/munmap 返回值和基本 accounting。

Linux 不能负责：

- 从 buddy/shmem/page cache 选择 backing PFN；
- 决定 object 是否存在、属于哪个 CID；
- 直接写 secure PTE；
- 在 mapping count 为零时决定 page 是否可以回收；
- 把 shared pool PFN 重新放回 Linux allocator。

### 7.2 首版优先 eager mapping

为了先闭合语义，建议第一版在 mmap/join 时由 Agent/OpenSBI 一次性分配并映射
全部页面，不先做 Linux-driven demand fault。这样可以减少以下不可信状态：

- fault 次序；
- Linux 提供的 fault PFN；
- object page 与 offset 的延迟绑定；
- 部分 fault 成功后的回滚。

后续确认 eager 版本正确后，再把同一个 trusted page lookup 放入 demand-fault
路径，而不是重新设计一套 fault 语义。

### 7.3 map/join 验证

OpenSBI 在提交 mapping 前至少验证：

1. 当前请求来自 `NACC_STATE_AGENT`，CID 非零；
2. target root 已 attached，且 root record CID 与 object CID 相同；
3. object id/generation、offset、length 有效；
4. VA、长度和 offset 页对齐，不与固定 Agent slot、vDSO/VVAR、已有 leaf 或
   其他 reserved range 重叠；
5. 目标 PTE slot 位于 secure PTP tree；
6. PFN 来自 fixed shared pool，且 descriptor 属于该 object；
7. 只允许 `PTE_U | PTE_R` 或 `PTE_U | PTE_R | PTE_W`，拒绝 `PTE_X`、
   special/devmap 和任意 Linux 提供的 PA；
8. bitmap tag 已在 PTE 对用户可见以前进入 `PRIVATE_DATA`。

Linux 即使知道 shared PFN，也不能通过普通 `SET_PTES` 把它安装到任意 root。
所有 secure-PTE prepare/commit 与 attach sweep 遇到 shared-pool PFN 时，都必须
查找 shared mapping record；不能把它按 ordinary private page 自动 enrollment。

## 8. 生命周期顺序

### 8.1 create

```text
validate Agent caller and CID
    -> reserve object id + generation
    -> allocate PEND frames only from shared allocator
    -> confirm every frame is in shared range and still PEND
    -> trusted zero in M-mode
    -> install object/page descriptors
    -> set frames to PRIVATE_DATA
    -> object becomes LIVE
```

在第一个 user PTE 可见以前，object 必须已经 LIVE，page descriptor 和 bitmap
必须一致。

### 8.2 map/join

```text
validate root/CID/object/VA/prot
    -> reserve pending mapping records and hold object/root transaction locks
    -> prevent the target address space from running during commit
    -> install secure PTEs in M-mode
    -> commit mapping records and counts
    -> perform required local/remote sfence
    -> allow the target address space to resume
```

多页操作必须有明确的 rollback。学术原型可以先限制单页或小批量事务，避免
出现前半段 PTE 已提交、后半段失败而 metadata 不一致。任何失败都必须在目标
地址空间恢复运行以前撤销已写 PTE 和 pending records。

### 8.3 unmap

普通 unmap 只移除该 root/VA 的 mapping：

```text
remove PTEs in M-mode
    -> remote/local sfence for affected address spaces
    -> remove mapping records
    -> decrement mapping_refs
```

如果 object 仍有 handle，即使 `mapping_refs == 0`，page 仍保持
`PRIVATE_DATA`，不能清零、改成 `NORMAL` 或回收到 Linux。

tag 没有变化时，本轮新增的 PFN-targeted QEMU invalidation 不会替代 PTE
unmap 所需的 sfence。两者是不同的同步事件。

### 8.4 destroy/reclaim

```text
object -> DESTROYING，拒绝新 mapping
    -> 撤销并 flush 所有剩余 mapping
    -> page tag PRIVATE_DATA -> PEND
    -> 确认无 mapping/handle/in-flight operation
    -> trusted zero in M-mode
    -> 清除 page/object metadata
    -> return frame to Agent shared allocator while keeping PEND
```

`PRIVATE_DATA -> PEND` 会触发当前 QEMU 的 targeted PFN invalidation，从而撤销
可能残留的 allowed physical aliases。回收完成后 PFN 仍为 PEND，Linux 在对象
不存在期间也不能访问；下一次分配仍要再次可信清零，不能因 allocator 记录为
free 就跳过清零。

### 8.5 fork、exec、exit

- fork：标准 `MAP_SHARED` 语义应让同 CID child 继承 mapping，但 child attach
  必须根据 parent mapping record 显式创建 child record；不能只因 copied PTE
  已指向 PRIVATE_DATA 就接受。
- exec：首版可以定义所有 NaCC shared mappings 都随旧 mm 撤销，handle 是否
  保留由显式 runtime 协议决定，不照搬 Linux FD table。
- exit：根据 PID/root 清理全部 mapping records；object 是否销毁仍由 handle
  lifetime 决定。
- `mremap`、部分 unmap、可执行共享页和跨 CID mapping 建议首版明确拒绝，待
  whole-object mapping 生命周期稳定后再增加。

## 9. 当前代码中必须先处理的缺口

### 9.1 当前 Agent base 同时承担了过多语义

当前 `0x180000000` 同时出现在 Agent linker、packed-image footer、OpenSBI load
address、domain/PMP region、`nacc_sagent` 和 bitmap end。不能只移动 CSR；首版
至少需要一致地处理：

- `agent/linker.ldS` 的 `AGENT_ENTRY`、reexec/trampoline 和 linker `eagent`；
- `agent/include/params.h` 中 Agent runtime allocator 的起点和上界；
- `pack_final_image.py` 的 `LOAD_ADDR` 和 footer load-address 校验；
- `opensbi/include/sbi/sbi_domain.h`、`sbi_agent.c` 的 load/copy/runtime-size 校验；
- OpenSBI root-domain/PMP Agent region 的 base/size，以及所有 hart 上写入的
  `nacc_sagent/nacc_eagent`；
- QEMU bitmap coverage end 和 Agent base/bound 常量；
- Makefile 中 legacy `0x17ff00000` Linux `memmap` 参数。

此外，`qemu/target/riscv/cpu_helper.c:nacc_qemu_pc_in_agent_window()` 当前用
`0x20000000` 对 `twin_entry` 向下对齐。Agent entry 移到 `0x190000000` 后，这个
算法仍会得到 `[0x180000000,0x1a0000000)`，错误地把前置 shared pool 计入合法
Agent S-mode PC window。该检查应改为实际的 `nacc_sagent/nacc_eagent` 边界，
不能继续依赖旧 512 MiB aperture 对齐。

### 9.2 现有 `SBI_EXT_AGENT_MMAP` 不能直接复用

当前 `sm_agent_mmap()` 接收任意 VA、PA、size 和 perm，直接调用 `mem_mmap()`；
ecall dispatch 也没有先证明调用者处于 `NACC_STATE_AGENT`。恶意 Linux 可以
主动发出相同 SBI funcid。

shared mapping 必须使用新的 typed interface，或先把该接口收紧到：

- Agent-state caller；
- attached root 和当前 CID；
- fixed shared-pool PFN；
- object mapping record；
- data-only PTE permissions。

不能把“funcid 名字里有 AGENT”当成调用者认证。

### 9.3 ordinary refcount arena 没有扩展空间

现有 4 MiB arena 几乎正好覆盖 ordinary tracked PFN，不能在不改布局的情况下
为数百 MiB shared pool 增加同样的 `u32` entry。需要按第 4.1 节拆分 ordinary
private refcount 与 shared descriptor。具体而言，`init_bitmap_region()` 不能再
用 `ppn_end - ppn_start` 同时定义 tag entry 数和 ordinary refcount entry 数。

### 9.4 通用 PTE 路径需要识别 shared PFN

当前 ordinary leaf 的默认策略会把未知 user PFN 纳入 PRIVATE_DATA。shared pool
PFN 必须是显式类别：

- 合法 shared mapping 按 object record 提交；
- 未找到 record 的 shared PFN mapping 一律拒绝；
- attach sweep、fork child attach、PTE replace、unmap 和 root teardown 都必须
  使用相同分类。

### 9.5 object metadata 必须位于 Linux 不可写区域

object/page/mapping table 应由 OpenSBI 的 `pvt_mem` 或 Agent-private control
memory 承载，不能放在 user-visible shared pool，也不能相信 Linux VMA/file
结构作为 authority。

### 9.6 并发和多 hart

object table、page allocator、PTE transaction 与 bitmap transition 需要统一
锁顺序。至少要避免：

- 一个 hart destroy，另一个 hart 同时 join；
- PTE 已安装但 mapping record 尚未 commit；
- 最后一个 handle 判断和新 map 竞争；
- page 已回收到 PEND freelist，但旧 hart 仍持有 allowed mapping。

当前 QEMU 的 PFN-targeted invalidation 解决 tag transition 的缓存一致性，不
自动解决 object/PTE transaction 的并发原子性。

### 9.7 shared PEND 不能走 ordinary refcount helper

当前 ordinary `PRIVATE_DATA` acquire/retire 路径与 `u32` PTE refcount 绑定，并会
在最后一个 ordinary reference 消失时把 tag 退回 `NORMAL`。shared object 不能
复用这一生命周期。需要提供 shared-range-only 的 typed transition helper：

- 只接受 fixed shared pool PFN；
- 在同一锁/事务中核对 shared-page descriptor 和 object state；
- 允许 `PEND -> PRIVATE_DATA` 和 `PRIVATE_DATA -> PEND`；
- 不索引 ordinary refcount arena，也不自动转成 `NORMAL`；
- 通用 copy/PTE/sweep 路径遇到 shared PEND 时只能拒绝，不能把它自动 promote。

## 10. 实施顺序

### 阶段 1：重定位和底层边界

1. 拆分 total reserve、shared pool、Agent private 和 tail metadata 常量；加入
   `shared_end == nacc_sagent`、地址页对齐和范围不重叠的构建期断言。
2. 把 Agent image/linker/footer/load/reexec 起点迁移到 `0x190000000`，保持顶部
   semantic/refcount/immutable 绝对地址不变。
3. 把 domain/PMP Agent region 缩为 `[0x190000000,0x1a0000000)`，写入
   `nacc_sagent=0x190000000`、`nacc_eagent=0x19ff00000`，并在所有 hart 同步。
4. 把 QEMU Agent S-mode PC window 收紧到真实 base-and-bound；确认 shared pool
   不再被 Agent-range U-mode deny 或 Agent-PC 身份检查覆盖。
5. 将 Makefile 的 legacy reservation 改为
   `memmap=1024M$0x180000000`，继续从 Linux buddy 功能性排除整段预留内存。
6. 扩展 tag coverage 到 `0x190000000`，得到 `0x44000` metadata；把 ordinary
   refcount coverage 独立固定在 `0x180000000`，确认 `pvt_mem.start` 为
   `0x1a0044000`。
7. 在 Linux 启动前将整个 shared pool 初始化并清零为 PEND，建立独立 frame
   allocator；断言初始化后 shared range 中没有 NORMAL/ROOT_L0 PFN。
8. 先完成 Agent、OpenSBI、QEMU 编译和启动回归，确认现有非共享 NaCC workload
   在新 Agent 地址上仍可运行，再进入 object/mmap 实现。

### 阶段 2：最小 object 与 eager mapping

1. 实现 fixed-size object/page/mapping table 和 generation-bearing handle。
2. 实现 Agent-authenticated create/map/unmap/destroy typed ecalls。
3. 先支持 page-aligned、whole-object、RW、eager mapping。
4. 由 OpenSBI 直接提交 secure PTE，不接收 Linux-chosen PFN。
5. 完成 rollback、sfence、PEND/PRIVATE transition 和每次分配/回收的可信清零。

### 阶段 3：Linux mmap compatibility

1. 增加 NaCC `MAP_SHARED` VMA 路由和 object handle 保存。
2. mmap 时调用 eager map；munmap/exit 时调用 trusted unmap。
3. 明确拒绝 `PROT_EXEC`、`mremap`、跨 CID、partial object mapping 等未支持
   组合。
4. 保持 VMA/RSS/accounting 兼容，但不把 Linux metadata 当成安全事实。

### 阶段 4：多进程生命周期

1. fork child mapping inheritance；
2. exec/exit cleanup；
3. mapping 为零但 object 仍存活；
4. stale handle/generation；
5. 多 hart join/destroy 竞争；
6. 确认需要后再实现 demand fault 和 partial mapping。

## 11. 首版验收条件

布局和启动检查：

- Agent entry 和 `nacc_sagent` 为 `0x190000000`，`nacc_eagent` 仍为
  `0x19ff00000`；所有 hart 值一致；
- shared pool 恰为 `[0x180000000,0x190000000)`，不落入 Agent PMP region 或
  Agent base-and-bound；
- bitmap metadata size 为 `0x44000`，OpenSBI `pvt_mem.start` 与 QEMU overlay
  均为 `0x1a0044000`；
- 启动初始化后每个 free shared PFN 均为 PEND，Linux/普通 U/Agent S 对其
  load/store/fetch 均失败，只有 M-mode 可以清零；
- relocated Agent 的 code、heap、semantic 和 refcount page 仍对 U/Linux 拒绝，
  现有非共享 NaCC workload 不回归。

功能正例：

- 同 CID 两个非 fork 进程映射同一 object，在不同 VA 上互相观察写入；
- mapping 全部消失后 object 仍可再次 map，内容保持；
- destroy 后 frame 清零并能被新 object 安全复用；
- fork child 按定义继承 shared mapping；
- 一个进程退出不影响其他合法 mapping。

安全负例：

- Linux direct map、kernel alias、S-mode load/store/AMO/CBO 访问 shared PFN 被拒绝；
- 普通 U-mode 或非 NaCC 进程映射同一 PFN 被拒绝；
- protected U-mode 映射 Agent code/heap/semantic/refcount PFN 被拒绝；
- Linux 直接调用 shared/Agent mmap funcid 被调用者检查拒绝；
- Linux 提供任意 PA、越界 offset、重叠 VA、`PROT_EXEC`、错误 generation 被拒绝；
- 其他 CID root 对 object 的 map 被 OpenSBI 拒绝；
- shared PFN 通过通用 PTE update 或 attach sweep 偷渡但无 mapping record 时被拒绝；
- destroy 后旧 PTE/TLB/handle 不能访问复用后的 frame；
- PEND frame 对所有非 M-mode 访问 fail-closed；
- Linux 在 object 创建前直接访问任意 free shared PFN 也被拒绝，而不是只在
  `PRIVATE_DATA` 生效后才被拒绝。

一致性检查：

- object page 数、page descriptor、mapping records、PTE 数和 mapping refs 可
  在 debug build 中互相核对；
- 任意失败路径不会留下既不在 free allocator 也不在 transaction/object 中的
  PEND orphan、已安装但未记录的 PTE，或含旧数据却已复用的 page；
- shared pool 初始化完成后不出现稳态 NORMAL/ROOT_L0 tag；
- QEMU SMP 测试覆盖 tag transition 和跨 hart stale alias；
- shared pool PFN 永远不进入 Linux buddy/page-cache/shmem allocator。

## 12. 暂不覆盖的范围

首版不宣称支持：

- 跨 CID shared memory；
- 完整 POSIX shm、tmpfs 或 file-backed `MAP_SHARED`；
- 每进程 ACL 或同 CID 内部互不信任；
- executable shared mappings；
- swapping、migration、memory pressure reclaim；
- device DMA/IOMMU protection；
- 任意 partial unmap/mremap；
- 通用 per-PFN ownerCID。

其中，跨 CID 防护最终需要 owner/ACL 或访问时 CID 绑定。首版虽然不增加通用
per-PFN ownerCID，仍必须通过 object CID 和 root record 拒绝其他 CID 的 PTE
建立；否则当前 bitmap 的 `PRIVATE_DATA` 访问规则会允许任何 protected U-mode
访问被恶意植入其页表的同一 PFN。

## 13. 论文表述建议

该方案可以描述为：

> NaCC reserves an Agent-managed physical pool for explicit intra-container
> shared mappings immediately below the Agent-private base. Shared frames are
> protected by the PFN bitmap, while the following Agent code and control
> region remains protected by the existing base-and-bound registers.
> Monitor-owned object and mapping metadata authorize same-CID roots and govern
> object lifetime. Linux retains only the mmap/VMA compatibility shell and
> never selects or owns shared backing frames.

不能描述成：

- bitmap 本身实现了 shared object ownership；
- 任意 `MAP_SHARED` 都自动安全；
- Linux shmem/page cache 已被保护；
- 当前原型已经支持跨 CID 或完整 POSIX shared memory。

## 14. 最终建议

下一步先实现“前置 fixed shared pool + 后置 relocated Agent + PEND-reserved
初始化”，并把它作为一个独立布局阶段验证；随后再实现 minimal eager object
mapping，不先进入 Linux demand-fault 或 POSIX shm 兼容。这样可以用最少的新
机制验证最关键的安全性质：

1. shared pool 与 Agent-private base-and-bound 在地址上严格分离；
2. Agent private/control page 继续与 user/Linux 隔离且无需 U-mode 例外；
3. free shared page 从启动后即为 PEND，live shared page 为 PRIVATE_DATA，Linux
   对两者的任意 alias 都由 bitmap 拒绝；
4. shared data page 只能经 trusted object mapping 被同 CID protected U-mode
   使用；
5. object lifetime 不再错误绑定到最后一个 PTE reference；
6. 整个方案只移动现有 `sagent` 边界，不增加 CSR，也不修改标准 PMP 语义。
