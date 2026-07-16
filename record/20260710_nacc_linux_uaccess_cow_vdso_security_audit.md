# NaCC Linux 内存集成与安全边界说明

日期：2026-07-10

实现校正与复验：2026-07-12

本文面向论文整理和后续设计讨论，不要求读者预先了解 Linux 内存管理或
NaCC 源码。它总结当前原型采用的机制、已经能够说明的性质、仍需加强的
边界，以及 vDSO/VVAR 等特殊映射为什么需要单独处理。

本文采用以下原型假设：

- 初始 ELF、受保护根页表和页表层次由独立的完整性机制确认。
- 本文重点讨论进程进入受保护状态以后，由 page fault、fork、COW 和
  unmap 等操作引入的动态页面。
- 当前 workload 1-8 已通过，说明所覆盖的正常功能路径可以运行，但这
  不等于已经完成针对恶意 Linux 的安全证明。

## 基本概念

- `VM_NACC_APP`：Linux 对 VMA 的路由标记，帮助现有匿名内存、page
  fault、fork 和回收路径进入 NaCC 分支。
- `PTE_NACC`：Linux 页表项中的软件标记，用于保存和传播“这是私有页”
  的生命周期信息。它不是硬件权限位。
- PFN bitmap：Monitor 维护的物理页状态，是硬件执行访问控制时真正
  参考的状态。
- `NORM`：普通页，Linux 可以按正常方式访问。
- `PRIV`：私有数据页，Linux 的原始 S-mode load/store 应被拒绝。
- `PEND`：可信复制过程中的过渡状态。页面已经可能接收秘密，但尚未
  完成最终私有 PTE 提交。
- public leaf：经过 Monitor 接受、但不需要保密的用户映射，例如只读
  ABI 数据或不可变公共代码。

## A. 结论摘要

1. NaCC 当前路线在原理上能够闭环，不需要重新设计 Linux page fault
   或 PFN bitmap。正确的安全决策点已经位于 OpenSBI 提交受保护 PTE
   之前。

2. `VM_NACC_APP` 和 `PTE_NACC` 的合理定位是 Linux 路由与生命周期
   缓存，而不是最终安全依据。最终决定应由 Monitor 根据受保护地址
   空间、目标 PFN 状态以及经过认证的 public mapping 信息作出。

3. 普通匿名 demand fault 的时间顺序是合理的：Linux 可以先分配和清零
   一个普通页，因为此时其中没有应用秘密；在该页对受保护用户态可用
   之前，OpenSBI 将 PFN 转成私有状态并提交 PTE。用户随后产生的秘密
   已受到 bitmap 保护。

4. 当前实现已经取消 `U+W+!X` 近似。attach sweep 会把除显式
   public/system、special/devmap、reserved-system 和 `PROT_NONE` 等例外
   以外的 ordinary resident leaf 纳入 bitmap；attached root 后续安装的
   ordinary leaf 也默认进入 `PRIV`，与 `U/W/X` 形状无关。Linux 的
   `VM_NACC_APP/PTE_NACC` 是路由和生命周期便利信息，不是该决定的安全
   前提。

5. 受保护地址空间不要求所有用户页都是 `PRIV`。经过 Monitor 验证的
   ELF 公共部分、vDSO text 和 VVAR 可以作为 public/system leaf 存在。
   论文应明确区分“私有应用数据”和“经过验证的公共用户映射”。

6. 显式 uaccess 的基本方向已经落实：Linux 不直接读取或写入私有 PFN，
   而由 OpenSBI 验证地址和方向后代为复制、读取、写入或清零。对
   `filemap_read -> copy_page_to_iter` 的 private kernel alias，Linux 也改走
   typed ecall；OpenSBI 将源 PFN 绑定到当前 attached root 的 CID，并要求
   它出现在同 CID 的某个 attached root 的可读私有 user leaf 中。当前
   ecall 仍未绑定到经过认证的具体 call site/用途，因此暂时不能声称已经
   抵抗恶意 Linux 构造任意请求。

7. COW 的关键顺序也是合理的：目标页在写入 confidential bytes 前先
   进入 `PEND`，成功提交新 PTE 后再进入 `PRIV`。当前尚缺 PEND 的完整
   硬件拒绝、失败回滚和退出清理。

8. 对当前支持的 ordinary leaf，可以声明动态默认保护由 Monitor 在
   attached-root 状态下兜底，且 S-mode 对 `PRIVATE_DATA` 的 raw
   load/store/AMO/CBO trap 一律 fail-closed；合法访问必须走 typed ecall。
   仍不能声明的是“所有特殊 mapping 都已有通用认证分类”“任意恶意
   Linux ecall 都安全”以及“最后一个引用消失时一定先清零再公开”。

## B. 五条主要路径

### B1. 初始建立与后续 page fault

1. Linux 建立进程地址空间，并由独立完整性机制确认初始 ELF、根页表和
   必要的公共映射。

2. 进程进入受保护状态前，OpenSBI 扫描已有用户 leaf，并为需要保密的
   resident page 建立 bitmap 状态。扫描成功后，根页表进入 attached
   状态。

3. 后续匿名 page fault 发生时，Linux 分配一个新物理页并进行清零。
   这个阶段页面仍是 `NORM`，但其中尚无 confidential application data。

4. Linux 请求提交新的用户 PTE。OpenSBI 在真正写入 PTE 前检查目标页
   是否属于私有类别、已有私有状态或可信复制的过渡状态。

5. 对私有页，OpenSBI 先更新 PFN bitmap 和引用状态，再提交带
   `PTE_NACC` 的 PTE。由此保证用户获得写权限以前，物理页已经受到保护。

6. 对经过认证的公共映射，Monitor 可以允许其保持 `NORM`。这类例外必须
   来自可信语义或完整性记录，而不能只依赖 Linux 声称该 VMA 是什么。

当前实现已经按以下规则执行，而不再使用 `U+W+!X` 权限近似：

> attached protected address space 中的新 ordinary user leaf，若不属于
> Monitor 已认证的 public/system mapping，则在对用户可见前进入 protected
> state。

### B2. Linux 从私有用户页读取

这一类操作包括 `get_user` 和 `copy_from_user`。

1. 普通 Linux 通常通过用户 VA 读取，并依赖 SUM 允许 S-mode 访问用户
   leaf。

2. 对私有 PFN，硬件 bitmap 应阻止这种原始访问。Linux helper 转而向
   OpenSBI 发出显式读取请求。

3. OpenSBI 解析当前用户 VA，确认它指向可读私有 leaf；批量复制时还要
   确认目标是普通、可写的 kernel buffer。

4. OpenSBI 在可信模式中完成数据移动，并把结果返回 Linux。

这条路径避免 Linux 通过普通 load 直接接触私有 PFN，但安全性还取决于
请求是否被绑定到合法进程、合法方向和合法用途。当前原型对此绑定不足，
因此不能把显式 `copy_from_user` 描述成已经抵抗恶意内核的完整接口。

### B3. Linux 向私有用户页写入或清零

这一类操作包括 `put_user`、`copy_to_user` 和 `clear_user`。

1. Linux helper 先请求 OpenSBI 检查目标用户地址和写权限。

2. 如果目标 PTE 已经可写，OpenSBI 可以在可信模式中完成写入或清零。

3. 如果目标页因 fork/COW 处于只读状态，OpenSBI 返回 locked 类结果，
   Linux 触发 writable fault，建立新的私有页后重试。

4. unsupported 情况可以回退到普通路径，但只有在确认目标不是私有页时
   才是安全的；其他失败应当终止、返回错误或明确重试。

当前不同 helper 对失败的处理并不完全一致，有的返回错误，有的记录日志，
有的会触发 fatal failure。后续应统一为可解释的失败与重试协议。

### B4. Linux 的直接 S-mode 访问

需要区分两种完全不同的访问：

- 通过用户 VA 的 uaccess：最终 leaf 带用户权限，Linux 通常需要 SUM。
- 通过 kernel direct-map、kmap 或 supervisor alias 的 raw access：
  最终 leaf 是 supervisor mapping，不依赖 SUM。

PFN bitmap 位于这两种 VA 形式之下。因此，只要同一物理页已经是 `PRIV`，
Linux 无论使用用户 VA 还是 kernel alias，都不应获得原始 load/store
权限。SUM 只能影响普通页表权限检查，不能成为私有 PFN 的授权依据。

硬件拒绝后会产生 access fault。当前实现对来自 S-mode、目标为
`PRIVATE_DATA` 的 raw load/store/AMO/CBO trap 统一重定向给 Linux，不再
根据 SUM 或 VA 高低在 M-mode 模拟。只有 typed ecall 才由 OpenSBI 代劳。
这闭合的是 raw-access fallback，不等于显式 ecall 已经具备完整的恶意
Linux 调用授权。

Agent 与普通 Linux 都运行在 S-mode，但不具有相同身份。Agent 在指定
执行状态和受保护区域内执行受控操作；Linux 状态下的任意 S-mode 指令
不应因为特权级相同就获得 Agent 权限。

### B5. fork、COW、PEND 与回收

1. fork 后，父子进程可以暂时共享同一个私有 PFN。对应 PTE 被写保护，
   Monitor 为共享 mapping 维护私有引用计数。

2. 发生写 fault 时，Linux 分配新页，并请求 OpenSBI 从旧私有页复制。

3. OpenSBI 先把目标 PFN 标成 `PEND`，再复制 confidential bytes。目标
   不能继续是 `NORM`，否则 Linux 可以在复制完成后直接读取；它也不能
   提前作为普通 `PRIV` 完成引用，因为此时 PTE 事务尚未提交。

4. 新 PTE 成功提交后，目标页进入 `PRIV` 并获得正式引用。旧 PFN 在仍有
   父进程、子进程或其他合法 mapping 时继续保持私有。

5. 最后一个私有 mapping 被移除时，理想顺序应是：禁止旧翻译继续使用，
   确认没有剩余私有引用，在可信模式中清零，然后才把 PFN 发布为 `NORM`。

当前原型已实现 PEND-before-copy 和基本引用计数，但尚未完整实现 PEND
中止恢复、事务回滚以及 zero-before-NORM。

## C. 当前可以成立的 invariants

在正常 secure-PTE 路径和原型假设下，可以确认：

1. 对 attached root 中除明确例外外的 ordinary resident leaf，bitmap
   状态在 PTE 对用户可见之前建立；该规则不依赖 `U/W/X` 组合。
2. `PTE_NACC` 在 fork、写保护和正常权限变化中能够传播私有生命周期。
3. COW 目标在 confidential copy 前进入 PEND，而不是保持 NORM。
4. 稳定的 `PRIV` PFN 会在硬件访问检查中区别于普通页；检查基于最终
   PFN，而不是某个特定 VA alias。
5. vDSO text 和 VVAR 不会被当作普通 private-anonymous page 处理。
6. vDSO text 是不可变公共代码映射；VVAR 是内核维护的只读公共数据映射。
7. workload 1-8 证明当前规则覆盖的 fork、uaccess、文件读取和共享内存
   等功能路径可以运行。
8. 来自 Linux S-mode 的 `PRIVATE_DATA` raw trap 不再被 Monitor 模拟；
   2026-07-12 的严格回归中也没有出现 strict-deny 命中，说明所覆盖路径
   已由显式 helper/ecall 完成。

这些 invariant 不包括恶意 Linux 的完整授权安全、PEND 永久不可访问、
回收前必然清零或所有 PTE/refcount 变化具有原子回滚。

## D. 论文表述与当前原型的边界

| 主题 | 可以采用的表述 | 暂时不应采用的表述 |
|---|---|---|
| Linux flags | 用于复用 Linux 原生 VMA、fault 和生命周期路径，不是 ordinary leaf 默认保护的安全前提 | Linux flags 已经覆盖所有特殊 mapping 语义 |
| Monitor 权限 | Monitor 对 attached root 的 ordinary leaf 兜底维护 PFN 状态 | 当前已经独立识别所有特殊页面语义 |
| 用户地址空间 | 可以同时包含私有数据和经验证的公共 leaf | 所有用户 leaf 都是 PRIV |
| uaccess | OpenSBI可代替合作式 Linux 操作私有数据 | 对恶意 Linux 的任意 ecall 已完全安全 |
| direct access | 硬件按最终 PFN 拒绝，S-mode PRIVATE_DATA trap fail-closed | 显式 ecall 因而自动具备完整用途授权 |
| COW | PEND-before-copy 顺序已经建立 | PEND 失败、退出和回收已全部事务化 |
| reclaim | 使用引用计数跟踪正常 fork 共享 | 最后引用消失时必然先清零再 NORM |
| vDSO/VVAR | 采用专门的公共/不可变语义 | 已形成适用于所有 kernel-injected mapping 的通用框架 |

论文可以讲清楚设计原则和原型路径，但应避免把“计划中的 Monitor
完整性分类”写成已经覆盖全部 Linux mapping 的实现事实。

## E. 尚未闭环的安全问题

后续加强可按以下优先级进行：

1. **uaccess 授权**：把显式复制绑定到当前受保护进程、合法方向、合法
   user range 和受控 kernel buffer 用途，避免将一个通用复制 ecall 变成
   非预期的数据导出接口。

2. **authenticated public mapping**：ordinary leaf 已不再依赖 `U/W/X`
   启发式；下一步是把 ELF 和其他例外统一绑定到 Monitor 维护的 manifest
   或语义记录。本文按学术原型假设初始 ELF 已通过完整性检查，因此这不
   阻塞当前 ordinary-data 结论，但不能把该假设写成已实现的通用机制。

3. **跨地址空间/CID 共享所有权**：当前 kernel-alias 读取允许同 CID 的
   attached root 为源 PFN 提供反向私有映射证明，足以覆盖本次父 shell 与
   子 exec 共享 file-backed 页的路径。bitmap 本身仍没有通用的 per-CID
   owner set，跨 CID 共享、同 PFN 多 CID 映射和恶意重映射需要独立设计与
   负面测试。

4. **PEND 生命周期**：硬件拒绝、提交失败回滚、中止清零和进程退出回收
   应形成完整事务。

5. **安全回收**：先撤销可达性，再确认最后引用，可信清零，最后发布
   `NORM`。

6. **失败处理**：PTE commit、批量操作和回收失败需要统一返回、重试或
   终止语义，避免 Linux 在 Monitor 拒绝后继续更新本地 accounting。

这些问题说明当前仍是研究原型，但不否定整体路径。它们集中在现有
Monitor prepare/commit、uaccess 授权和回收边界上，可以逐步加强。

## F. vDSO/VVAR 修改的原因、机制和测试需求

### F1. 为什么必须单独处理

vDSO 和 VVAR 不是普通匿名私有页：

- vDSO text 是跨进程共享的只读可执行代码。
- VVAR 是用户只读、但需要由内核持续更新的数据。

ordinary leaf 的默认规则是私有化；vDSO/VVAR 必须作为显式语义例外。
普通 file-backed leaf 不能仅因为只读或可执行就自动保持 public；若内核
确实需要读取其受保护 kernel alias，应使用经过检查的 typed ecall。

### F2. 当前机制

- vDSO text：OpenSBI建立一个 Monitor 管理的不可变 RX 镜像。多个受保护
  地址空间可以共享该镜像；它不是每个进程单独的私有页，也不使用
  `PTE_NACC`。
- VVAR：继续使用普通 `NORM` PFN，以用户只读形式映射。Monitor 记录其
  root、VA、PFN 和允许的权限形状，使 Linux 可以通过 supervisor mapping
  更新数据，而用户不能写入或执行。
- fork：子进程不直接继承父进程中依赖 root 语义的最终映射，而是在自己的
  root 下重新建立或验证。
- exec 和 munmap：映射随新地址空间重新建立；移除时相应语义记录失效。

这说明 protected address space 可以包含经过 Monitor 验证的 public
leaf。它也修正了“所有 user-data leaf 都是 PRIV”的过强设计表述。

### F3. 是否已经一般化

当前实现是“具有通用方向的专门处理”，还不是完整的
kernel-injected-user-mapping 框架。可复用思想包括：

- 按 root、VA、PFN 和权限记录 mapping 语义；
- 对未知 special mapping 默认拒绝；
- 区分 private data、public untrusted data 和 immutable system code。

仍然专门化的部分包括 vDSO/VVAR 的识别方式、镜像来源和生命周期。论文
可以把它们作为一般问题的代表性实例，但不应声称已覆盖未来所有特殊映射。

### F4. 测试需求

功能测试应覆盖：

- vDSO 时间相关接口与显式 syscall 结果一致；
- fork 前后、首次 fault 前后、重复 exec 和父子退出顺序；
- VVAR 在内核持续更新时不会触发 private bitmap 拒绝；
- vDSO 最终只读可执行，VVAR 最终只读不可执行；
- munmap、mremap、time namespace 和多核更新。

安全负面测试应覆盖：

- 伪造 VVAR PFN、权限或 VA；
- 篡改 vDSO 来源、权限或最终映射；
- 尝试写入不可变 vDSO、执行 VVAR；
- 复用其他进程的 mapping 记录；
- 语义记录耗尽、失败提交和重复回收。

完整性机制最终还应把 ELF/vDSO public mapping 绑定到可信 manifest 或
digest，而不是只依赖 Linux 提供的来源信息。

## G. 2026-07-12 实现校正与验证

本轮实现校正包括：

- attach sweep 和 attached-root 动态更新统一保护 ordinary resident
  leaf，删除 `U+W+!X` 条件；
- 增加 private kernel alias 到 kernel buffer 的 typed ecall，修复
  `__memcpy -> copy_page_to_iter -> filemap_read -> bprm_execve`；
- private kernel source 必须由当前 attached root 的可信 CID 授权，并在
  同 CID 的某个 attached root 中找到 `U|R|PTE_NACC` leaf；
- 所有 Linux S-mode `PRIVATE_DATA` raw load/store/AMO/CBO trap 统一
  fail-closed，不再依赖 SUM 或地址高低模拟。

构建结果：`make opensbi` 和 `make linux-update` 均通过。

严格专项：

- `docker run --security-opt seccomp=unconfined --rm busybox sh -c
  'cat /etc/hostname && echo done'` 输出 hostname 与 `done`，code 0；
- 日志：
  `logs/strict_raw_deny_cat_01_20260712_023347_{qemu,vm}_20260712_023758.log`。

最终 workload 1-8：八项均 `status=ok`，业务输出分别包含
`kernel_read_done`、`kernel_write_done`、`fork_private_done`、hostname、
`alpha`、`13 /etc/hostname`、`6` 和 `ping`。日志前缀为
`logs/strict_raw_deny_w1_8_0[1-8]_20260712_...`。对全部 QEMU/VM 日志的
联合扫描没有发现 strict raw deny、ecall copy deny、access fault、Oops、
panic 或动态库读取错误。

该验证证明所覆盖功能路径不再依赖 raw trap 模拟；它不是恶意 Linux
任意 ecall、跨 CID 共享或安全回收的完整安全证明。

## H. 可返回写文章 agent 的内容

### 可以写成实现事实

1. Linux 使用 mm/VMA/PTE 软件状态把原生 page fault、fork、COW、uaccess
   和 unmap 路由到 NaCC 路径。
2. Monitor 维护每个物理页的保护状态；硬件根据最终 PFN、执行身份和
   NaCC 状态实施访问控制，而不是把 `PTE_NACC` 当作硬件权限位。
3. attached root 中除明确语义例外外的 ordinary leaf 与 `U/W/X` 无关，
   PFN 在受保护 PTE 提交前进入 private state。
4. 显式 uaccess 允许 OpenSBI 在可信模式中代替合作式 Linux 操作私有页；
   private kernel alias 读取也使用 typed ecall 和同 CID 反向映射证明。
5. fork 共享采用私有 PFN 引用计数；COW 目标在可信复制前进入 PEND。
6. vDSO text 使用共享不可变公共镜像；VVAR 使用受语义约束的只读公共页。
7. protected address space 可以同时包含 private data、public untrusted
   data 和 immutable system code。
8. 当前实现已通过 workload 1-8，证明所覆盖的正常功能路径能够运行。
9. Linux S-mode 对 `PRIVATE_DATA` 的 raw load/store/AMO/CBO trap 当前统一
   fail-closed；最终回归没有命中该拒绝路径。

### 暂时不能声称

1. 不能声称当前实现已经抵抗恶意 Linux 的所有显式 uaccess 请求。
2. 不能声称 PEND 具有完整硬件隔离和失败恢复。
3. 不能声称 private page 在公开复用前一定完成可信清零。
4. 不能声称当前已有适用于 ELF 和所有 kernel-injected mapping 的通用
   authenticated manifest。
5. 不能声称同一 PFN 的跨 CID 共享和 owner-set 语义已经闭合。
6. 不能声称 protected address space 中经过认证的 public/system leaf 也
   必须私有化。
7. 不能声称当前原型已经形成完整的 malicious-host 机密性与完整性证明。

### 建议返回的简短结论

NaCC 的整体路线仍然成立。Linux flags 用于复用原生内存管理路径，
OpenSBI 在受保护 PTE 提交前完成最终 PFN 状态转换，硬件再按 PFN bitmap
阻止 Linux 的原始访问。普通匿名页在仍为空白时可以由 Linux 分配和清零，
但必须在应用写入秘密前进入 private state；COW 目标则在可信复制前进入
pending state。ELF 公共部分、vDSO 和 VVAR 可以通过独立完整性或语义
验证作为 public leaf 存在，因此不应把所有用户页统一描述为私有页。

当前原型已经把 ordinary leaf 的动态分类从 `U+W+!X` 收束为 attached-root
默认保护，并把 Linux S-mode raw trap 改成 fail-closed；filemap/exec 所需
读取通过同 CID 校验的 typed ecall 完成。仍需加强的是显式 ecall 的用途
授权、通用 authenticated public mapping、跨 CID 共享、PEND 回滚和安全
回收。这些属于现有 Monitor 决策点上的局部完善，不要求推翻当前架构。
