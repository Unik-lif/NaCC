# NaCC 单容器多进程生命周期实现阅读笔记

日期：2026-07-11

本文用于补充论文 Implementation 章节，范围限定为当前原型中的
single-container private-memory substrate 及其多进程生命周期。它不重复
Design 章节的概念流程，也不按 SBI 编号写接口手册，而是说明代码实际把
Linux、OpenSBI 和 Agent 放在什么顺序上、哪些状态在正常路径中已经闭合、
哪些边界仍只是原型实现。

本文只记录当前代码能够支持的事实。为便于写作代理直接使用，正文不列源码
路径和行号。这里的 “child” 均指 child process 或 child protected task，
不指另一个 Agent。

## 1. 可以写进 Implementation 的核心事实

### 1.1 Registration、首次 exec 与后续 reexec

- NaCC 把“进程登记”和“受保护地址空间接管”拆成两个时刻。容器运行时在
  最终 exec 前调用注册系统调用；Linux 把当前任务置为准备状态，并把 CID
  和 PID 登记到 OpenSBI。此时 monitor 只创建进程记录和 per-PID 执行上下文，
  尚未接管某个 mm，也没有开始受保护用户态执行。

- 当前内核注册入口实际只消费 CID。运行时补丁虽然准备了 manifest identity、
  digest 和 layout 等附加参数，但这些参数尚未贯通到当前注册系统调用和
  monitor 验证路径。因此，论文可以把 ELF/manifest 完整性作为系统假设或
  独立机制，却不能声称当前注册调用已经完成了端到端 measurement。

- exec 构造新 mm 时，Linux 立即把该 mm 标为 NaCC-active，并预留固定的
  Agent 用户虚拟地址槽。根页表仍由 Linux buddy allocator 分配，但在开始
  搭建用户页表层次时就登记为受保护 root；后续用户侧 non-root PTP 则直接
  从 monitor 的专用 PTP 池获取。

- 只有 exec 成功提交后，Linux 才根据任务状态选择首次 invoke、fork-child
  attach 或 reexec。这样，失败于 point-of-no-return 之前的 exec 可以恢复原
  任务状态，未完成的新 mm 也按普通 mm 销毁流程回收，不会提前把用户控制流
  交给 Agent。

- 第一个受保护任务会触发完整 invoke。OpenSBI 确认当前 SATP 对应已登记的
  root，检查低半用户页表的 non-root PTP 都来自安全池，扫描已经 resident 的
  leaves，安装固定 Agent mapping，然后以完整启动参数进入 Agent。Agent 完成
  全局初始化后显式通知 monitor；这一 ready 状态使后续任务不再重复初始化
  全局 Agent。

- 后续 reexec 复用同一个 PID/CID monitor 记录，但使用 exec 新建的 root。
  OpenSBI 对新 root 重新执行 root 确认、PTP 结构检查、resident-leaf enrollment
  和 Agent mapping，然后只进入轻量 reexec stub。该 stub 刷新当前 SATP、
  用户寄存器指针、kernel return context 和 hart-local trap context，不再重复
  Agent 全局内存初始化、完整启动参数传递或首次 ready 协议。

- exec 替换旧 mm 时，同一 PID 的进程登记不会被注销。旧 mm 先按页表拆除
  路径退休 private leaves、non-root PTP 和旧 root；新 mm 随后以同一进程记录
  重新 attach。也就是说，exec 更新的是 protected address-space context，
  不是 container/process identity。

### 1.2 fork child 的两条 attach 路径

- 普通 fork 保留 Linux 原生的 `dup_mm`、`copy_page_range` 和 COW 建立过程。
  child 的 root 在分配时单独登记，用户 non-root PTP 仍来自 monitor 池；固定
  Agent VMA 不从 parent 复制，而是在 child attach 时重新插入。

- parent 在唤醒 child 以前，先把 child 的全局 PID 登记到同一 CID 下。这样
  child 第一次运行 attach 时，OpenSBI 可以核对“该 PID 已存在且属于预期
  CID”，而不是由 child attach 临时创建身份记录。

- 普通 fork child 在第一次返回用户态之前进入 `ATTACH_FORKED_CHILD` 路径。
  OpenSBI 验证 child root 和 secure PTP tree，扫描 child leaves，映射 Agent，
  加载 child 的 monitor thread context，并进入轻量 Agent stub。该 stub 更新
  child-specific trap/return contract 后直接返回 child 用户态；它不执行首次
  Agent 初始化。

- 如果 child 在第一次普通用户态返回前执行 exec，则使用 `INVOKE_CHILD`。
  它与普通 child attach 共享 root/PTP/leaf 验证和 Agent mapping，但不接收
  child 用户寄存器上下文，也不跳入 Agent stub，而是把 monitor 状态切回
  Linux 后返回 exec 路径。这是一个更窄的 attach 变体，不是 child Agent。

- `REEXEC`、`INVOKE_CHILD` 和 `ATTACH_FORKED_CHILD` 都复用了首次 invoke 的
  地址空间确认部分，但裁掉了全局 Agent 初始化。三者的差别主要在最终控制流：
  reexec 和普通 fork child attach 进入轻量 Agent stub；fork-before-exec 的
  child attach 留在 Linux 中继续完成 exec 返回。

### 1.3 Protected PTP 与 PTE install

- Linux 继续拥有 mm、VMA、`struct page`、RSS、rmap、LRU 和 memcg 等软件
  元数据。NaCC 没有另建一套 shadow VM policy；它只改变受保护页表页的来源
  和最终 PTE 写入方式。

- root 与 non-root PTP 采用不同生命周期。root 是 Linux 分配的普通页，在
  mm 建立早期由 monitor 标成 ROOT；non-root PTP 是 monitor 专用池页，Linux
  为其建立必要的 `ptdesc` 和页表 accounting，但 S-mode 只能读取，不能直接
  写入。

- RISC-V 的通用 PTE install、write-protect、exchange、get-and-clear 和
  accessed-bit update primitives 是集中拦截点。只要目标 slot 位于 secure
  PTP，Linux 就把 candidate PTE、目标 slot、VA 和 root context 交给 OpenSBI，
  而不是在各个 fault、fork、mprotect 和 unmap 分支中分别重写页表。

- `_PAGE_NACC` 随 candidate PTE 穿过这些通用 primitives。它表达 Linux 对
  “private anonymous leaf”的路由结果，并在 fork、write-protect 和 COW 中
  传播；OpenSBI 可以接受、拒绝或在提交结果中补上该 bit。它不是硬件权限位，
  也不是 PFN 进入 protected state 的最终依据。

- OpenSBI 在提交前检查目标 slot 是否位于受保护 PTP 区、PTE leaf 编码是否
  合法、leaf 是否错误指向 secure PTP 或 reserved system memory，以及 special、
  VVAR、immutable vDSO 和 PROT_NONE 等语义约束。root 的低半 slot 只能为空或
  指向 secure non-root PTP，不能直接安装 user leaf。

- 对当前 private candidate，OpenSBI 在写 PTE 前增加 monitor private reference，
  把 PFN 置为 PRIV，并提交最终带 `_PAGE_NACC` 的 PTE。若旧 PTE 的 private PFN
  被替换或移除，旧 PFN reference 也在同一个 prepare/commit 路径中递减。

- 当前动态 page-fault 加固只在 root 完成 attach 后启用。对 attached root 中
  ordinary `U+W+!X` leaf，OpenSBI 即使没有收到 Linux 的 `_PAGE_NACC`，也会
  默认纳入 private state；初始 exec 建图阶段仍由 resident sweep 和单独的
  ELF/public-mapping 完整性假设处理。这个规则避免把 file text、只读文件页
  和其他公共 mapping 过度私有化，但它仍是原型中的权限形状近似，而不是
  完整 authenticated mapping policy。

### 1.4 Demand fault 与 resident-page enrollment

- 对新的 private-anonymous demand fault，Linux 仍执行原生匿名页分配、清零、
  memcg charge、RSS 增加、new-anon-rmap 和 LRU insertion。NaCC 只要求该 fault
  使用单个 4 KiB candidate，而不使用共享 zero page 或匿名大页批量提交。

- Linux 在最后构造 candidate PTE 时加入 private routing bit，然后调用通用
  PTE install primitive。OpenSBI 在 PTE 对用户态可见之前完成 NORM-to-PRIV
  和 private-reference acquire。因而在正常成功路径中，Linux 的内存元数据
  已经建立，而 confidential user writes 尚未发生。

- 首次 invoke、reexec 和 child attach 之前都有 resident sweep。Linux 先识别
  private-anonymous VMA 并为已有 ordinary leaves 提交 private candidate；OpenSBI
  随后独立检查页表结构、PFN role 和已登记的 exceptional mappings，再把通过
  的 root 标为 attached。只有 attached 之后，动态默认私有规则才生效。

- 为避免 Linux 通用代码通过 direct map 解引用受保护 PFN，private PTE 在
  `vm_normal_page` 类通用查询中被排除；需要做 RSS、rmap、fork 或 teardown 时，
  NaCC 专门分支再从 PFN 恢复对应 `struct page`。这保留 Linux accounting，
  同时把数据移动留给 monitor-mediated helper。

### 1.5 fork、COW、PEND 与 private refcount

- fork 的 parent write-protect 仍由 Linux 原生 COW 逻辑触发。写保护同一个
  private PFN 不增加 monitor reference；把 parent 的 protected PTE 安装到
  child root 时，OpenSBI 为 child 的独立 PTE mapping 增加一个 reference。
  因此 monitor refcount 跟踪 protected PTE mappings，而不是 PID 数量或 Linux
  mapcount。共享同一个 mm 的线程不会因为线程数增加而增加 PFN reference。

- private write fault 仍进入 Linux 的普通 writable-fault 和 `wp_page_copy`
  路径。Linux 分配并 charge 新 folio，但页复制 helper 会先询问 OpenSBI：若
  source 和 destination 都是 NORM，则继续原生 kmap copy；若 source 是 PRIV，
  则由 OpenSBI 完成整页 trusted copy。

- trusted COW copy 的当前成功顺序是：检查 source 为 PRIV、destination 为
  NORM；先把 destination 标成 PEND；复制 confidential bytes；Linux 重新取得
  PTE lock 并确认旧 PTE 未变化；清除旧 PTE；提交指向 destination 的 private
  PTE；OpenSBI 在最终提交时把 PEND 提升为 PRIV，并建立第一个正式 reference。

- PEND 的实现含义只是 trusted copy 与 final PTE commit 之间的 quarantine
  state。它没有接管 Linux COW policy，也没有替代 Linux 的 folio、rmap、LRU、
  mapcount 和 TLB ordering。正常提交后，Linux 继续完成 new-anon-rmap/LRU
  insertion，并在 PTE replacement 之后移除旧 folio 的 rmap。

- 旧 PFN retirement 发生在旧 protected PTE 被 clear/exchange 时。若 parent、
  child 或其他 PTE 仍引用该 PFN，monitor refcount 保持非零，PFN 继续为 PRIV；
  只有最后一个 protected PTE reference 被移除时才进入最后回收分支。

### 1.6 munmap、exit、exec teardown 与 PTP recycle

- munmap、COW replacement、exit 和 exec-old-mm teardown 都复用 protected
  get-and-clear primitive。OpenSBI 先根据可信旧 PTE 递减 private reference，
  再把 slot 清空；Linux 随后继续原生的 RSS/rmap/TLB/free-page bookkeeping。

- non-root secure PTP 释放时不返回 Linux buddy。Linux 清理本地 `ptdesc` 状态
  后，把 PFN 放入 per-CPU reclaim list；列表满、完整 `exit_mmap` 或特定 stack
  relocation 收尾时批量送给 OpenSBI。专用池 allocator 仅检查 PFN 的范围与
  对齐，随后清零整页并重新挂回 secure PTP free list。

- root 不进入 non-root PTP batch。它必须在用户 leaves 已拆除、non-root PTP
  已回收且 mm 的最后引用消失后，先退休 root semantic records 和 ROOT role，
  再由 Linux 释放原来的 buddy page。这一差异来自 root 与 non-root PTP 的
  allocator、身份记录和 lifetime 都不同。

- 进程退出时，`exit_mm` 先完成上述地址空间 teardown，之后 Linux 才调用
  `UNREGISTER`。后者只移除 PID/CID process record 和 per-PID monitor thread
  context，不代替 private leaf、PTP 或 root 的回收。多线程共享 mm 时，mm
  teardown 仍由 Linux 的最后 mm reference 决定，而每个登记 task 可分别注销。

### 1.7 Linux memory compatibility

- `VM_NACC_APP` 在 NaCC-active mm 的 private anonymous mmap、brk 和初始
  resident walk 中设置，并按 Linux VMA split/merge/fork 规则自然传播。它让
  demand fault、COW、mprotect 限制和 private-page accounting 进入少数共同
  分支；特殊 mapping、shared mapping、PFNMAP/MIXEDMAP 和 file-backed mapping
  不使用这一标记。VMA 销毁时无需单独清 bit，因为 VMA 本身随 mm 生命周期
  消失。

- explicit uaccess 集中在 RISC-V 的 `get_user`、`put_user`、raw bulk copy 和
  `clear_user` primitives。普通 Linux 会在访问 user leaf 前打开 SUM；NaCC
  helper 在同一 SUM-enabled 窗口先请求 OpenSBI。若 VA 解析为 NORM，monitor
  返回 unsupported，helper 回到原生汇编；若解析为 PRIV，则由 monitor 完成
  scalar read/write、bulk copy 或 clear。

- OpenSBI 当前会检查调用来自 S-mode、SUM 已打开、user VA 在当前 SATP 下
  解析为具有正确方向权限的 private leaf，以及 bulk operation 的 kernel
  buffer 在同一页表下解析为 NORM supervisor leaf。操作按页边界切块，返回
  Linux 已完成字节数。

- 对 `put_user` 和 `copy_to_user` 的只读 COW leaf，OpenSBI 返回 locked。Linux
  临时清除 SUM，调用标准 writable-prefault 触发 COW，恢复 SUM 后最多重试一次。
  清 SUM 的目的是让 prefault 明确进入 Linux writable-fault path，而不是再次
  被误识别为正在进行的 SUM-on data operation。

- raw S-mode dereference 与 user-VA uaccess 必须分开描述。user-VA helper 通常
  依赖 SUM；kernel direct-map、kmap 或 supervisor alias 不依赖 SUM。当前硬件
  模型在 Linux execution state 下按最终 PFN role 拒绝 PRIV load/store，并把
  access fault 送到 OpenSBI；OpenSBI 对显式 helper 提供 typed operation，但
  raw trap fallback 仍保留部分 SUM-off load/store、AMO 和 zeroing 模拟，尚未
  形成统一的 default-deny policy。

### 1.8 vDSO 与 VVAR

- Linux exec 仍按原生 ABI 建立相邻的 VVAR 和 vDSO special VMAs。它们不是
  private anonymous mapping，也不应因为位于用户地址空间就自动变成 PRIV。

- 对 NaCC vDSO text，Linux 只提供原始系统 vDSO PFN 列表和预期用户 VA。
  OpenSBI 检查 root context、页数、PTE slot 形状、source PFN 为 NORM、mapping
  为 user RX 且不可写，然后将 text 复制到 monitor 管理的全局 immutable
  region，并直接把目标 PTE 改指向该副本。多个受保护 mm 可以复用同一份
  immutable image；它不带 `_PAGE_NACC`，也不是 per-process PRIV page。

- immutable vDSO region 对 S/U 可读执行、不可写，M-mode 可在 adoption 时
  初始化。后续 protected PTE update 只允许保持完全相同的 immutable leaf 或
  将其移除；NaCC mm 的 vDSO mremap 被拒绝，避免重新引入 Linux 原始 backing。

- VVAR 保持系统共享的 NORM PFN。每次 fault 前，OpenSBI 为当前 root 记录精确
  的 VA、PFN、CID 和只读 user-special permission shape；只有匹配该 record 的
  PTE 才能提交。因为 PFN 仍为 NORM，Linux 可以通过正常 supervisor mapping
  更新时钟数据，而 protected U-mode 只能只读访问。

- fork 不复制 parent 已驻留的 vDSO/VVAR PTE。child 保留 VMA 布局，但在自己的
  root 下重新 adoption 或 record：vDSO 复用全局 immutable image，VVAR 重新
  绑定 child root。exec 同样为新 root 重建；munmap/exit 清 PTE 后，root retire
  最终退休该 root 的 semantic records。

- 这组修改修复的具体 invariant 是：root-scoped exceptional mapping 不能把
  parent 的 monitor authorization 原样带进 child root，也不能让 generic
  private sweep 把 VVAR 误当 confidential page，或让 vDSO fault 回 Linux 可变
  backing。它已经形成可复用的“root + VA + PFN + permission”语义记录思路，
  但 mapping 识别、adoption 和 fault handler 仍是 vDSO/VVAR 专用实现，尚不是
  覆盖所有 kernel-injected user mapping 的通用框架。

## 2. 建议论文怎么组织

### 2.1 Registration and exec attachment

突出“identity registration 与 mm attachment 分离”这一实现选择。先说明
runtime 只登记 CID/PID，成功 exec 才 attach 当前 root；再说明第一个任务执行
full Agent initialization，而 reexec 和后续任务只刷新 address-space/trap
context。这里不需要再列 SBI 表，只需对比 full invoke 和 lightweight attach
裁掉了哪些初始化工作。

### 2.2 Protected page fault and PTE installation

突出 Linux bookkeeping 未被替换，以及 NaCC 通过 architecture PTE primitives
集中提交，而不是在每个 VM branch 中复制安全逻辑。按“Linux prepares folio
and candidate PTE -> OpenSBI validates -> bitmap/refcount before PTE visibility”
写出顺序，并说明 attached-root dynamic default 是为了让 Linux hints 只承担
routing，而不是唯一决定 post-attach writable user page 是否私有。

### 2.3 Fork and COW

先写 Linux 原生 fork write-protect 与 child page-table copy 保留，再写 child
PTE commit 如何增加 monitor mapping reference。COW 段落只需强调 trusted
high-page copy 插入在原生 copy helper 中，以及 PEND-before-copy、final-commit
promotion 和 old-PTE retirement 的实际顺序。不要把 PEND 描述成新的 COW
allocator 或 COW policy engine。

### 2.4 Teardown and recycling

按 leaf -> non-root PTP -> root -> process record 的顺序写。差异化实现点是：
leaf removal 复用 PTE exchange；non-root PTP 由 Linux 收集、OpenSBI 批量清零
归池；root 保持受保护直到 mm 最后引用；`UNREGISTER` 最后只清 task identity。
同段应主动注明当前 private-data zero-before-NORM 尚未实现，以免与 Design
目标混写。

### 2.5 Linux memory compatibility

把 routing hints、uaccess 和 kernel-injected mappings 放在 lifecycle 之后，
作为“保留原生 Linux address space 的工程适配”。先说明 VMA/PTE hint 如何
收束 hook，再说明 explicit uaccess 与 raw alias 的差别，最后用 vDSO/VVAR
展示 protected address space 可以同时包含 private data 和 monitor-accepted
public/system leaves。

## 3. 不要 overclaim 的地方

1. **注册时完整性验证尚未贯通。** 当前注册内核入口只使用 CID；运行时准备
   的 manifest/digest/layout 参数没有被当前 monitor registration 消费。不能
   把“计划或独立假设中的 ELF measurement”写成当前 REGISTER 已实现的事实。

2. **non-root PTP 没有完整 owner metadata。** 当前 monitor 能证明目标 slot
   位于 secure PTP pool，也能给 root 记录 CID，但尚不能普遍证明某个 PTP
   属于哪一代 root/CID、某个 `ptep` 对应哪个受信 VA，或调用者有权修改它。
   batch reclaim 同样没有 per-PTP owner 与可靠的 duplicate-free 验证。owner、
   generation、ancestry 和 cross-container authorization 仍不完整。

3. **PTE transaction 不是原子的。** PFN acquire/retire 发生在 raw PTE write
   之前；多项 SET 可以部分成功，exchange 竞争也没有完整 accounting rollback。
   Linux 的部分 wrapper 只记录失败后继续，不能声称 candidate、bitmap、PTE
   和 Linux accounting 具有全事务回滚。

4. **动态默认分类仍是近似。** attached root 的 `U+W+!X` 规则覆盖当前普通
   writable user data，但不是 authenticated mapping contract。可写可执行页、
   已有 private PFN 的 alias、复杂 file-COW、未知 special mapping 和未来的
   kernel-injected mapping 仍需要更一般的 monitor-owned policy。

5. **PEND 目前不是完整 quarantine。** 正常顺序确实是 PEND-before-copy 和
   PEND-to-PRIV-on-commit；但当前硬件模型只拒绝稳定 PRIV，没有把 bitmap value
   3 当作同样不可由 Linux S-mode 访问的状态。若 COW copy 后 PTE recheck 失败，
   也没有通用的 PEND 清零、退回 NORM 或 orphan sweep。

6. **最后引用回收没有可信清零。** 当前 private refcount 归零时直接把 PFN
   从 PRIV 改回 NORM，未在同一 monitor 临界区清零 confidential contents。
   non-root PTP 回池会清零，但不能把这个事实外推到 private data page。

7. **explicit uaccess 不是完整 capability。** bulk `copy_from_user` 等操作会
   验证当前 SATP 翻译、方向、SUM、private source 和 NORM kernel buffer，但
   传入 PID 与 caller PC 没有参与批准，bulk path 也没有统一的 active scope、
   root owner 或 CID binding。恶意 Linux 仍可能构造 ecall，把当前 root 中的
   private bytes 复制到任意可写 NORM kernel buffer。

8. **trusted high-page copy 的授权也不足。** 正常 COW 使用正确 source/destination，
   但 monitor 的 fast path 主要依据 source 为 PRIV、destination 为 NORM，没有
   完整证明 source PFN 就是给定 root/VA 的旧 leaf，也没有 transactional abort
   token。它适合描述合作式 Linux 的正常 COW path，不适合描述成任意恶意
   ecall 均不可滥用。

9. **raw trap fallback 尚未统一 fail closed。** Linux-state PRIV access 在硬件
   模型中会 fault，但 OpenSBI 仍模拟部分 SUM-off raw load/store、AMO 和 cache
   block zero；SUM-on fallback 才更严格地回送 Linux。不能声称所有 direct-map
   和 alias dereference 都只允许 typed SBI operation。

10. **Agent 权限与论文目标仍有差距。** 当前 QEMU 将 Agent execution state
    设为独立 MMU index，并只对 Linux state 执行 PRIV bitmap deny，因此 Agent
    state 在模型中可越过 Linux-only PFN check；semantic/refcount carve-out 也给
    S/U 读写权限。Agent 的代码确实通过 SBI 请求页表 mapping，secure PTP 也
    对 S-mode 只读，但当前实现不足以证明“Agent 不能直接写 protected metadata
    或 confidential data page”这一更强 invariant。

11. **vDSO adoption 还不是 cryptographic verification。** monitor 检查 root、
    PFN role、slot 和权限，并把第一份 source image 复制后封存；后续复用依据
    source PFN list 匹配。当前没有在 adoption 内核验 expected digest，因此
    “原始 vDSO 内容经过密码学完整性检查”仍需由独立启动 measurement 补齐。

12. **VVAR 是 public/untrusted ABI data。** 当前机制保证 mapping identity 和
    permission shape，不保证内核提供的时间内容可信。论文不能把它写成 trusted
    time source。

13. **shared-memory IPC 和 cross-container isolation 不在当前闭环内。** 当前
    private refcount 足以表达同一 container 内 fork 产生的 PTE sharing，但没有
    完整 same-CID shared-object model、跨 CID owner enforcement 或共享内存
    declassification protocol。workload 能运行不等于 secure IPC 已实现。

14. **Agent multicore 仍是 prototype hardening。** per-PID context save/load、
    hart-local trap refresh 和 Agent-ready reuse 已有实现，但并发 Agent entry、
    stale context/generation、PID reuse 和多 hart 竞争还没有系统性安全测试。

## 4. 可直接写进论文的英文句子草稿

### Registration and exec

NaCC separates process registration from protected address-space attachment.
The runtime registers a CID/PID pair before the final exec, whereas attachment
is delayed until Linux has committed the new `mm`; only the first protected
task performs full Agent initialization, while later execs use a lightweight
re-entry path to refresh the root and trap-return context.

### Protected page-table installation

Linux retains its native VMA, page-allocation, RSS, rmap, LRU, and memcg
bookkeeping.  The RISC-V page-table primitives redirect writes to protected
page-table pages into OpenSBI, which validates the candidate leaf and updates
the PFN role and private reference count before making the PTE visible.

### Fork and COW

Fork continues to use Linux's native write-protection and page-table copying
logic, while each child PTE commit acquires a monitor-side reference to the
shared private PFN.  During COW, the existing high-page copy helper invokes
OpenSBI, which marks the destination pending before copying confidential bytes
and promotes it to private only when the replacement PTE is committed.

### Teardown

Protected leaf removal is routed through the same mediated PTE exchange path,
so the monitor retires the corresponding private reference before Linux
finishes its normal RSS and rmap teardown.  Non-root protected page-table pages
are returned in batches to a monitor-owned zeroing allocator, whereas the
Linux-allocated root remains protected until the final `mm` reference is
released.

### Linux routing hints and uaccess

`VM_NACC_APP` and `_PAGE_NACC` are Linux-side routing hints rather than trust
anchors: they concentrate private-anonymous handling in common VMA, fault, and
PTE primitives.  Explicit user-access helpers transfer private data through
OpenSBI, while ordinary non-private accesses retain the native SUM-enabled
RISC-V path.

### Kernel-injected mappings

NaCC treats the vDSO and VVAR as public system mappings rather than private
anonymous data.  vDSO text is copied into a monitor-managed immutable image,
whereas VVAR remains a kernel-updatable normal PFN whose root, virtual address,
physical page, and read-only permission shape are recorded by the monitor.

### Prototype boundary

The current prototype establishes the normal single-container fork/COW/exec
lifecycle, but it does not yet provide transactional rollback for failed PTE
commits or pending COW copies.  Owner-tagged PTP metadata, capability-scoped
bulk uaccess, zero-before-publication for retired data pages, and complete
cross-container authorization remain hardening work.

## 5. 需要补实验或补代码的问题

### P0：在论文提交前优先闭合

1. **PEND deny 与 abort cleanup。** 让硬件/模拟模型把 PEND 与 PRIV 一样拒绝
   Linux S-mode raw access；增加 fault-injection test，在 trusted copy 后、PTE
   commit 前主动制造 race/abort，验证目标页被清零并安全回收，没有 orphan
   PEND。

2. **zero-before-NORM。** 把最后 private reference 的 retirement 改成可信顺序：
   撤销 PTE 可达性、确认 refcount 为零、monitor 清零、最后发布 NORM。测试应
   重新分配同一 PFN，并证明普通 Linux 无法观察前一进程内容。

3. **收紧 `copy_from_user` 和 trusted high-page copy。** 至少绑定当前 registered
   PID/CID、attached root、user VA leaf、方向和受限 kernel destination scope；
   high-page copy 还应证明 source PFN 与 root/VA 的旧 PTE 一致。加入恶意 ecall
   负面测试，尝试把任意 PRIV PFN 导出到 NORM kernel buffer。

4. **PTE/PTP owner 与失败原子性。** 为 non-root PTP 增加 root/CID/generation
   owner metadata，验证 `ptep -> root -> VA` 关系，并为 SET/UPDATE 的 bitmap
   side effects 提供 rollback 或 fail-stop transaction。负面测试包括错误 root、
   跨 root PTP、stale generation、重复 reclaim 和部分 batch failure。

5. **修正失败传播。** SET_PTES、WRPROTECT、PTP reclaim 和 root retire 不能只
   记录错误后让 Linux 继续本地 accounting；需要统一成明确的 retry、fatal
   stop 或可回滚错误协议。

### P1：补足 Implementation 证据

6. **当前树的 lifecycle matrix。** 在已有 workload 1-8 通过的基础上，再运行
   repository 中的 repeated fork/exec、same-PID reexec、mmap/munmap、pthread/
   shared-mm、abnormal exit 和 repeated-container loops。每轮同时核对 private
   PFN、secure PTP、root 和 process/thread-context live counters 回到 baseline。

7. **fork refcount 顺序测试。** 构造 parent/child 以不同顺序 munmap/exit，验证
   shared PFN 在第一个进程退出后仍为 PRIV，最后 mapping 消失后才退休；再覆盖
   parent-first、child-first、多代 fork 和 COW 后各自退出。

8. **exec failure 与旧/新 root 测试。** 覆盖 exec 在提交前失败、提交后失败、
   fork-child immediate exec 和连续 reexec，确认旧 root 只退休一次、新 root
   只 attach 一次、PID registration 不丢失且没有 stale semantic records。

9. **vDSO/VVAR 功能测试。** 比较 vDSO 与强制 syscall 的 time/getcpu 结果，
   覆盖 fork、exec、time namespace、signal delivery/rt_sigreturn 和 child refault。
   现有 workload 通过可作为兼容性证据，但不能替代这些定向 ABI tests。

10. **vDSO/VVAR 安全负面测试。** 尝试写 vDSO backing、把 immutable leaf 改成
    writable/supervisor mapping、mremap vDSO、替换 VVAR PFN、给 VVAR 增加 W/X、
    伪造同形状 special PTE，以及跨 root 复用 semantic record；全部应被 monitor
    拒绝。另需加入 expected digest test，才能支持“原始 vDSO 已完整性验证”。

### P2：原型范围外或后续 hardening

11. **把 vDSO/VVAR 抽象成 kernel-injected mapping class。** 保留统一的 root、
    CID、VA、PFN、permission 和 generation record，再让 vDSO/VVAR 只提供各自
    的 classifier/adoption policy，减少继续增加特殊 hook 的风险。

12. **Agent least privilege。** 让真实硬件模型和 prototype 都明确区分 Agent
    code execution、metadata update 和 confidential data operation；目标是 Agent
    也不能凭 S-mode/NACC_STATE 直接写 private data 或 monitor metadata，只能
    使用窄的 OpenSBI operation。

13. **multicore 与 stale-context tests。** 覆盖并发 fork/exec/exit、跨 hart
    migration、PID reuse、重复 attach、Agent entry overlap 和 context generation
    mismatch。现有 per-PID context 机制可以作为起点，但不能替代这些测试。

14. **shared-memory 与 cross-container model。** 在论文当前范围内只声明
    single-container fork-derived sharing。same-CID shared objects、System V/POSIX
    shared memory、跨 CID denial 和 declassification 需要独立设计与实验，不应
    用 workload 8 的功能成功代替安全闭环。

## 结论

当前代码已经给出一条可以在 Implementation 章节讲清楚的主线：identity
registration 与 mm attachment 分离；Linux 保留 VM policy 和 accounting；
secure PTE primitives 集中进入 OpenSBI；fork 复用原生 COW，monitor refcount
跟随 child PTE；trusted copy 通过 PEND 串接到 final commit；teardown 按 leaf、
non-root PTP、root、process record 的顺序完成；vDSO/VVAR 作为 root-scoped
public/system mappings 单独处理。

这条主线足以支撑“single-container private-memory substrate with multi-process
lifecycle”的实现叙述。论文暂时不能把它扩展成恶意 Linux 下完整的 uaccess
capability、原子 PTE transaction、安全 PEND/retirement、Agent least privilege、
cross-container isolation 或 secure shared-memory IPC。
