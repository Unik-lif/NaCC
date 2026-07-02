# NACRE VDSO/VVAR/PROT_NONE semantic metadata design

## 背景和问题

这次要解决的不是给 PFN bitmap 增加一个新状态。当前 2-bit PFN bitmap 已经没有空闲语义：

- `0`: normal
- `1`: root L0
- `2`: private data
- `3`: private copy pending / transient copy state

因此不能把 VDSO/VVAR 或 PROT_NONE 继续塞进 bitmap。bitmap 应继续作为快速的硬件侧 PFN role classifier；更复杂的映射语义必须放到受保护 metadata 中。

真正的问题是：Linux 可以通过 VDSO/VVAR、`pte_special`、`PROT_NONE` 等路径制造普通 bitmap 无法表达的页表状态。如果 monitor 只看 Linux VMA flags、Linux PTE bits、`_PAGE_NACC` 或 `pte_special`，就可能把 Linux 提供的未验证状态当成可信事实。

目标是建立一条小型固定容量 exceptional-mapping metadata 路径，只覆盖异常映射，不复制完整 Linux VMA。

## 当前代码观察

- RISC-V VDSO 初始化在 `linux/arch/riscv/kernel/vdso.c`。Linux 先通过 `get_unmapped_area()` 选择用户 VA，然后安装 `[vvar]` 和 `[vdso]` special mappings。
- VDSO text mapping 的 backing page 来自 `vdso_info->cm->pages`。缺页时 `special_mapping_fault()` 返回 `vmf->page`，之后走普通 `finish_fault()` 安装 PTE。
- VVAR mapping 不同，它在 `vvar_fault()` 中调用 `vmf_insert_pfn()`，最终安装 `pte_special`。
- OpenSBI full private sweep 已经会拒绝 protected special/devmap leaf，但运行时 `SET_PTES` / `UPDATE_PTE` 路径仍需要基于 semantic metadata 的精确授权。
- Agent 当前 trap 入口能看到用户异常和 syscall register frame，但 Agent 代码还很简单，尚未维护 mmap/mprotect/munmap/mremap 语义表。
- 当前 `CSR_NACC_SAGENT/EAGENT` 覆盖 `SBI_DOMAIN_AGENT_REGION_BASE..SBI_DOMAIN_METADATA_REGION_BASE`。private refcount 区已经从 Agent physical region 尾部 carve out。新的 semantic metadata 和 immutable system page 区域应沿用类似 carve-out 思路。

## 设计目标

1. 不使用新的 bitmap value。
2. 不信任 Linux VMA/PTE 作为安全 authority。
3. 不复制完整 Linux VMA 树，只维护少量 exceptional mapping records。
4. Agent 可以维护靠近 syscall/trap 语义的 metadata。
5. OpenSBI/monitor 在真正页表更新边界强制执行 metadata。
6. VDSO text 对 NACRE 进程使用不可被 Linux 后续篡改的副本。
7. VVAR 不声明可信，只作为 public/untrusted exact special mapping。

## Protected region split

Agent physical region 不应再被视作单一用途区域。建议至少拆成以下逻辑子区：

### Agent runtime region

Agent 代码、栈、运行时数据。Linux 不可写。用户态不应映射或执行该区域。

### Semantic metadata region

Agent 可写，OpenSBI 可读并可在必要时初始化/清理。Linux 不可信，不能写入。该区保存少量 exceptional-mapping records。

这一区域的存在理由是：Agent 在 trap/syscall 语义附近工作，维护 `mmap(PROT_NONE)`、`mprotect(PROT_NONE)`、VDSO/VVAR adoption 等状态时，不需要每次都下陷到 monitor 做普通表操作。但最终安全判断仍由 monitor 执行。

### Immutable system page region

用于保存 adopted VDSO text 等 NACRE-owned system pages。它不是 Agent runtime，也不是 private application data。

目标权限形状：

- adoption/seal 前：Agent 或 monitor 可以写入初始化内容。
- seal 后：只允许目标用户 PTE 以 `U|R|X` 方式映射。
- Linux/S-mode 不得通过 direct map、supervisor mapping 或 writable PTE 修改该区域。
- OpenSBI 拒绝任何不匹配 semantic record 的映射。

注意：PMP/domain 权限通常把 S-mode 和 U-mode 作为 SU 统一处理，不能单独表达“U-mode 可执行但 S-mode 不可执行”。因此不能只靠 PMP permission；必须结合 monitor 对页表更新的强制校验，拒绝 Linux 把这些 PFN 映射成 supervisor/writable mapping。

### Private refcount region

沿用现有 private refcount carve-out。不要与 semantic metadata 或 immutable system pages 混用。

## Semantic record

记录建议使用小型固定容量 exceptional-mapping record table，存放在 Agent reserved semantic metadata region。为便于 Agent 和 OpenSBI 同时操作，第一阶段不要使用复杂指针结构，优先使用固定槽位和 index。

第一阶段目标是先把后续防御拉起来：adoption 之后，Linux 不能再通过 backing page 修改、PTE laundering、unknown `pte_special` 或 PROT_NONE 语义混淆绕过 monitor。启动加载阶段的 VDSO 完整性验证不放进本轮最小实现。

建议字段：

- `state`
- `root_pfn`
- `cid`
- `mm_generation`
- `va_start`
- `va_end`
- `class`
- `allowed_pte_flags`
- `pfn_count`
- `pfns[]`，固定小数组，用于 VDSO/VVAR exact PFN list
- `old_priv_pfn`，仅用于 `PROTNONE_PRIV`
- `flags`
- `refcount` 或 mapping count

第一阶段不记录 digest、不做 measurement、不保存 variable-length allocation pointer。若 VDSO/VVAR 页数超过固定 PFN 数组容量，先拒绝 adoption，而不是引入动态结构。

Required classes:

- `PROTNONE_EMPTY`: `mmap(PROT_NONE)`，当前没有 PFN。
- `PROTNONE_PRIV`: 已有 private page 转成 PROT_NONE，需要保留 old private PFN/refcount。
- `SYS_VDSO_TEXT`: adopted immutable VDSO text mapping。
- `SYS_VVAR_DATA`: exact public/untrusted VVAR data mapping。
- `AGENT_MAPPING`: monitor-installed agent mapping，如果后续需要记录。
- `DENY_SPECIAL`: 可选，显式拒绝某个 range。

## Agent and monitor responsibilities

### Agent responsibilities

Agent 负责靠近语义的一侧：

- 观察 syscall/trap intent，例如 `mmap`、`mprotect`、`munmap`、`mremap`。
- 对少量特殊区域维护 semantic records。
- 在 adoption 阶段辅助定位 VDSO/VVAR candidate mapping。
- 在 metadata region 中更新 exceptional-mapping records。

Agent 不应成为最终安全 authority。Agent 写入的 metadata 必须被 OpenSBI 在使用时校验，包括 root/cid、VA range、PFN role、PTE flags、状态机等。

### OpenSBI/monitor responsibilities

OpenSBI 负责执行：

- 所有安全页表更新都必须带有足够上下文：`root_pfn`、`cid`、`VA`、old PTE、requested PTE。
- 对普通 private pages 继续走 bitmap 快路径。
- 对 special/protnone/system mappings 查 semantic metadata。
- 未知 `pte_special` 默认拒绝。
- `pte_special` 指向 private PFN、root PFN、protected PTP、Agent runtime、immutable system page 的非法形态时拒绝。
- VDSO/VVAR/PROT_NONE 只有精确匹配 record 才允许。

### Agent-to-monitor commit boundary

Agent 可以准备 semantic records、定位 candidate mappings、分配或填充 reserved pages，但不能直接修改 secure PTP。任何会改变用户页表的最终 commit 都必须通过 OpenSBI PTE update path 完成。

VDSO adoption 尤其需要这个边界。替换用户 VDSO PTE 不只是普通写 PTP，它同时包含安全判定：

- caller 必须处于合法 Agent context。
- root/cid/mm generation 必须匹配当前 NACRE task。
- VA range 必须匹配待 adoption 的 VDSO text record。
- target PFN 必须属于 immutable system page region。
- requested PTE permissions 必须严格是 user RX，不能 writable，不能 supervisor-only。
- metadata record 必须从 pending 进入 sealed 状态。
- commit 后需要执行必要的 TLB fencing。

ABI 设计首选复用现有 PTE update ecall 路径，例如当前 Linux 使用的 `SET_PTES` / `UPDATE_PTE` 形状，而不是一开始就引入独立 Agent-only ABI。复用的前提是这些 OpenSBI handler 被升级为 semantic-aware：

- handler 不能只按 caller 名义区分 Linux/Agent，而是必须基于 root/cid/VA/PTE/metadata 做同一套强制校验。
- Linux 发起的普通 PTE update、Agent 发起的 adoption commit，最终都进入同一个 monitor enforcement point。
- 如果 caller 已经提供 `ptep_pa`，可以直接复用 `SET_PTES` / `UPDATE_PTE`。
- 如果 Agent 只有 VA/root 而没有 PTE slot PA，则需要让 OpenSBI 根据 root+VA walk 到 PTE slot；这可以作为现有 ABI 的扩展，或在必要时再添加一个窄的 helper ABI。

因此新 ABI 不是第一选择。只有在现有 PTE update ABI 无法可靠表达 root+VA walk、record slot/index、或 adoption state transition 时，才引入类似 `SBI_EXT_AGENT_ADOPT_VDSO` 的窄 ABI。

## VDSO design

VDSO 采用 copy-and-adopt，不做完整 Agent VDSO rewriting。

重要修正：不能只冻结 Linux 原始 VDSO PTE。只冻结 PTE 无法阻止 Linux 通过内核原始地址或 direct map 修改 backing bytes。因此 NACRE 进程应使用 NACRE-owned VDSO text 副本。

Flow:

1. Linux 原生 exec path 正常创建 `[vvar]` 和 `[vdso]` 用户 VA 布局。
2. 在第一次 user resume 前、secret provisioning 前进入 NACRE adoption phase。
3. Agent/monitor 定位 candidate VDSO text VA range。
4. 将 Linux 当前 VDSO text bytes 复制到 immutable system page region。
5. Agent 通过现有或扩展后的 OpenSBI PTE update ecall 请求 commit adoption。
6. OpenSBI 校验 caller/root/cid/VA/PFN/permissions 后，将目标用户 VDSO PTE 改指向 NACRE-owned immutable system pages。
7. OpenSBI seal `SYS_VDSO_TEXT` semantic record，包含 root/cid/generation、VA range、PFN list、RX permissions、state。
8. 后续 PTE 更新只能把该 VA range 映射到记录中的 PFN list，且权限必须是用户只读可执行，不可写。
9. Linux 不得再通过普通页表路径把该 VDSO VA re-fault 回 Linux 原始 VDSO page。

本轮设计接受 adoption 时刻的 VDSO bytes 作为 bootstrap input。它先解决 adoption 之后的篡改和重映射问题；启动加载时的 expected hash、digest、measurement、seal policy 以后再补。

Open issue:

- 需要确认实现层面如何绕过或替换 Linux `special_mapping_fault()` 的后续行为，避免 VDSO PTE 被清掉后重新 fault 回原始 `vdso_info->cm->pages`。

## VVAR design

VVAR 不作为 confidential/trusted data 保护。当前 prototype 不实现 trusted time，因此不能声称 VVAR 内容可信。

VVAR 处理策略：

- 不复制到 immutable system page region。
- 不标记成 private PFN。
- 不允许成为 generic `pte_special` bypass。
- 记录为 `SYS_VVAR_DATA`，class 标注 public/untrusted。

Record requirements:

- exact VA range
- exact PFN list
- allowed permissions: user readable only
- not writable
- not executable
- public/untrusted flag

Monitor enforcement:

- 如果 `pte_special` 精确匹配 `SYS_VVAR_DATA` record，允许。
- 如果 VA/PFN/range 不匹配，拒绝。
- 如果权限变成 writable/executable，拒绝。
- 如果 `pte_special` 指向 private/root/PTP/Agent/immutable VDSO/unknown PFN，拒绝。

## PROT_NONE design

RISC-V PROT_NONE 会保留 PFN 和高位软件 bit，同时清掉 present/permission 并使用 `_PAGE_PROT_NONE`。这意味着现有 bitmap/refcount 可能保留 private PFN，但 monitor 仍缺少显式语义：这是 empty PROT_NONE，还是隐藏 private PFN 的 PROT_NONE。

Case 1: `mmap(PROT_NONE)` with no PFN

- Agent 可记录 `PROTNONE_EMPTY`。
- 不改变 bitmap/refcount。
- 后续变成 accessible mapping 时，必须通过 OpenSBI 变成合法 private mapping。

Case 2: existing private page -> `PROT_NONE`

- Agent 观察 `mprotect(PROT_NONE)` intent。
- OpenSBI 读取 old trusted PTE。
- 保留 old private PFN/refcount。
- 记录 `PROTNONE_PRIV`，key 包含 root/cid/generation/VA。
- 写入 monitor 认可的 non-present/protnone PTE。

Case 3: `PROT_NONE` -> accessible

- OpenSBI 仅在 `PROTNONE_PRIV` record 匹配、old PFN 仍为该 root/cid 的 private PFN 时恢复合法 NACC PTE。
- 对 `PROTNONE_EMPTY`，后续 fault/commit 必须走普通 private allocation/tagging 路径。

## Fork/exec/exit behavior

Fork:

- Child root 继承或派生 semantic records。
- `SYS_VDSO_TEXT`: 可共享同一 immutable VDSO PFN list，并增加 mapping/refcount。
- `SYS_VVAR_DATA`: 继承后重新校验 exact VVAR mapping。
- `PROTNONE_PRIV`: 增加 old private PFN refcount 或创建 child-specific record。
- Unknown special mappings fail closed。

Exec:

- exec 开始新 mm generation。
- 旧 generation records 退休。
- fresh exec mm 在 adoption phase 创建新的 VDSO/VVAR records。

Exit:

- root teardown 时释放所有 semantic records。
- 不能泄漏 `PROTNONE_PRIV`、`SYS_VDSO_TEXT` refcount 或 immutable system pages。

## Data structure choice

第一阶段建议使用简单固定槽位 exceptional-mapping record table：

- record 数量上限小，例如按 container/process 数量乘一个小常数。
- lookup 可以 O(n)，因为 exceptional mappings 很少。
- 所有跨 Agent/monitor 共享字段使用 plain integer，不使用 Linux 指针。
- PFN list 可先定长，例如 VDSO/VVAR 页数有限；过长则拒绝。
- 每个 record 有状态机：`FREE`、`PENDING`、`SEALED`、`RETIRED`。
- 不在 record 中放 digest/hash 或动态分配指针。
- 不要求 Agent 维护完整 VMA tree；只记录 monitor 需要精确授权的少数 range。

后续如果 records 变多，再考虑按 `root_pfn` 或 VA range 建索引。

## Required enforcement changes

需要逐步改造 OpenSBI PTE update path：

- `sm_nacc_set_ptes`
- `sm_nacc_update_pte`
- `sm_nacc_wrprotect_ptes`
- `nacc_prepare_secure_pte_update`
- private sweep / `nacc_sync_private_tags`

核心要求是：monitor 判断不能只看 PTE 本身。它必须知道 root/cid/VA，并查询 semantic metadata。

## Tests

1. VDSO present，signal handler return 正常。
2. NACRE 进程 VDSO text PTE 指向 immutable system page 副本。
3. Linux 尝试把 adopted VDSO text 改成 writable 或换 PFN 被拒绝。
4. VDSO PTE 被清掉后，不会重新 fault 回 Linux 原始 VDSO page。
5. VVAR 可读，但 metadata 标记为 public/untrusted。
6. VVAR writable/executable mapping 被拒绝。
7. Unknown `pte_special` fail closed。
8. `pte_special` 指向 private/root/PTP/Agent/immutable PFN 被拒绝。
9. `mmap(PROT_NONE)` -> `mprotect(RW)` 正确提交 private PFN。
10. existing private -> `PROT_NONE` -> RW 保留内容和 refcount。
11. fork child VDSO/VVAR/PROT_NONE records 正确继承或派生。
12. exec/exit 后 semantic records 和 immutable pages 无泄漏。

## Non-goals

- 不实现完整 shared-memory object model。
- 不实现 trusted time。
- 不复制完整 Linux VMA。
- 不消耗 bitmap value `3` 或新 bitmap state。
- 不把 `pte_special` 泛化为通过条件。
- 第一阶段不实现 VDSO expected digest、measurement 或启动加载完整性策略。
- 第一阶段的 `SEALED` 只是 semantic record 状态，表示 adoption 已提交且后续 PTE 更新必须精确匹配该 record。

## Implementation phases

Phase 1: Design and ABI skeleton

- 定义 Agent reserved subregions。
- 定义 semantic record layout。
- 定义 Agent/monitor 访问规则。
- 决定复用现有 `SET_PTES` / `UPDATE_PTE` ecall 还是增加最小扩展；默认优先复用现有 PTE update path。
- 给 OpenSBI 增加 semantic lookup/validation helper。

Phase 2: Fail-closed special/protnone enforcement

- OpenSBI PTE update path 接入 semantic validation。
- Unknown `pte_special` 默认拒绝。
- VVAR record 只允许 exact public/untrusted mapping。
- PROT_NONE private preservation 接入 record。

Phase 3: VDSO adoption

- adoption phase 定位 VDSO text candidate。
- 复制到 immutable system page region。
- 不计算 digest，不引入 expected hash policy；adoption 时刻的 bytes 暂作为 bootstrap input。
- Agent 通过现有或扩展后的 PTE update ecall 请求 OpenSBI commit。
- OpenSBI 替换用户 VDSO PTE。
- OpenSBI seal metadata。
- 阻止后续 re-fault 回 Linux 原始 VDSO backing page。

Phase 4: lifecycle and tests

- fork/exec/exit cleanup。
- leak checks。
- targeted QEMU/log tests。

## Security argument

该设计防止 Linux VMA/PTE/special laundering 的关键点是：

- Linux 可以提供 routing hint，但不能提供 authority。
- bitmap 只表达普通 PFN role，不承载复杂语义。
- special mappings 必须匹配 monitor 可读的 semantic record。
- VDSO text 不再依赖 Linux 原始 backing page，而是使用 NACRE-owned immutable copy。
- 第一阶段不证明 adoption 前的 VDSO bytes 可信，只防止 adoption 后被 Linux 篡改或通过 PTE 路径换回原始 backing page。
- VVAR 被承认为 public/untrusted，只限制 mapping 形状，不声明内容可信。
- PROT_NONE 的 private PFN preservation 由 explicit record 表达，而不是从 Linux PTE/VMA 反推。

## Current implementation status after TASK_20260701_104059

当前代码只完成了一个 bounded first slice，不是完整的 Agent-owned semantic
metadata design。

已经完成的部分：

- OpenSBI 新增固定容量 semantic table，并把 `SET_PTES`、`UPDATE_PTE`、
  `WRPROTECT_PTES`、private sweep 等路径接入 root/VA-aware semantic
  validation。
- Agent/OpenSBI 物理布局已经切出 semantic metadata region、immutable
  system-page region、private refcount region；Agent runtime allocator 会停在
  semantic region 之前，避免覆盖这些保留区域。
- VVAR 走最小实现：Linux 在 VVAR fault 或 detach 已有 VVAR special PTE 时提供
  root/VA/PFN hint，OpenSBI 写受保护 record，并在后续 PTE 更新时强制 exact
  public/untrusted VVAR shape。
- Unknown `pte_special` 仍然 fail closed。NaCC private anonymous zero-page
  fault 和 private `/dev/zero` zero-source fault 不进入 semantic table，而是
  分配普通 private `PTE_NACC` leaf。
- NaCC private anonymous `mprotect(PROT_NONE)` 当前不做 monitor-side
  preservation；Linux 在 PTE mutation 之前返回 `-EACCES`，避免产生 OpenSBI
  无法证明的 `old=0` private-PFN PROT_NONE transition。

尚未完成的部分：

- Agent 还没有观察 `mmap`、`mprotect`、`munmap`、`mremap` 等 syscall/trap
  intent，也没有作为 semantic record producer 承接 mmap 语义。
- VDSO copy-and-adopt 还没有实现。当前只有 `SYS_VDSO_TEXT` record shape 和
  OpenSBI validation helper，没有 adoption phase、immutable copy、record seal、
  用户 `[vdso]` PTE replacement，也没有防止 PTE 被清后 refault 回 Linux 原始
  `vdso_info->cm->pages` 的完整机制。
- PROT_NONE private preservation 没有按原设计实现 explicit record 生命周期；
  当前策略是 Linux-side clean rejection。
- fork/exec/exit 下 semantic record 继承、派生、refcount、immutable page
  cleanup 仍未实现。
- semantic record capacity/high-watermark/table-full diagnostics 还没有补齐；
  压测多进程或 VDSO/VVAR 多页场景前应单独验证。

因此，当前状态应理解为：monitor 侧 enforcement scaffold 和 VVAR 最小防线已经
落地，zero-source private faults 被导回普通 private-page allocation 路径；完整的
Agent semantic ownership 和 VDSO 移花接木仍是后续任务。
