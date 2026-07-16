# NaCC bitmap 控制面安全缺口记录

日期：2026-07-13

状态：基于当前代码的静态检查记录。本文只记录当前实现事实、不足及必须满足
的安全约束，不代表已经确定后续 Agent-managed shared memory 的实现方案，也不
代表下列问题已经完成修复。

## 1. 背景与当前范围

本轮讨论最初来自同 CID 多进程显式共享，但进一步检查发现，需要先区分
bitmap 的两个职责层次：

1. **数据面访问控制**：当 PFN 被标记为 `PRIVATE_DATA` 时，硬件阻止 Linux
   S-mode 和普通非 NaCC U-mode 直接访问该物理页。
2. **控制面授权与生命周期**：谁可以把 PFN 标成或退出 `PRIVATE_DATA`，谁
   可以把该 PFN 安装到哪个 root/VA，以及何时可以安全回收。

当前 bitmap 数据面已经能够提供有意义的物理访问阻断，但 bitmap 的 2-bit tag
和 private refcount 本身不能表达 root、进程、CID、对象身份或一次 PTE 更新的
授权来源。当前 OpenSBI 控制面尚未把这些事实完整绑定。

当前实验主要运行单 CID。因而“同一 private PFN 被映射给另一个 CID”暂时不
是已覆盖 workload 中会自然出现的功能场景。但是：

- 单 CID 不会自动解决同 CID 多进程之间的默认不共享语义；
- 即使只有一个进程，恶意 Linux 仍可能重映射、降级 tag 或提前回收页面；
- 裸 PFN/root lifecycle 接口和 PTE slot 未绑定问题与 CID 数量无关。

因此，多 CID 尚未实现可以缩小当前声明范围，但不能作为忽略控制面验证的
依据。

## 2. 当前已经成立的数据面事实

以下机制在当前代码中已经存在：

1. QEMU 对 `PRIVATE_DATA` 的最终物理访问检查位于
   `qemu/target/riscv/cpu_helper.c`。当前允许 M-mode、Agent-state S-mode 和
   Agent-state protected U-mode，拒绝 Linux S-mode 与普通 U-mode。
2. `sm_prepare_user_pt()` 在 root attach 前检查 non-leaf PTP 来自 secure PTP
   区，并调用 `nacc_sync_private_tags()` sweep 已有 protected leaves。
3. attached root 后续安装 ordinary resident leaf 时，
   `nacc_prepare_secure_pte_update_for()` 不再依赖 `U+W+!X` 启发式；attached
   状态本身会使 ordinary leaf 进入 private tag/refcount 路径。
4. Secure PTP PMP 权限允许 Linux S-mode 读取但不允许写入，Linux 的 PTE 写入
   需要经过 OpenSBI ecall。
5. bitmap metadata 和 private refcount region 不由 Linux 直接写入。

这些事实支持如下有限结论：

> 只要 PFN 正确保持在 `PRIVATE_DATA`，Linux 不能通过 direct map、kernel
> alias 或普通 U-mode 代理直接读取和写入该页。

它们尚不能证明恶意 Linux 无法诱导 Monitor 错误地改变 tag、refcount 或 PTE。

## 3. 缺口一：已有 PRIVATE_DATA PFN 缺少新增映射授权

### 3.1 当前实现

QEMU 的 `nacc_qemu_private_data_access_allowed()` 只检查当前 privilege mode 和
`NACC_STATE_AGENT`，不读取 CID，也没有 per-PFN owner 信息。

OpenSBI 的 `nacc_prepare_secure_pte_update_for()` 在目标 root 已 attached 时，
会把 ordinary requested leaf 作为 private candidate。随后无论目标 PFN 原来是
`NORMAL` 还是已经是 `PRIVATE_DATA`，都可能调用
`nacc_bitmap_acquire_private_data()` 增加 refcount并接受映射。

`nacc_bitmap_acquire_private_data()` 只维护 tag 和计数，不检查此次新增映射的
root、VA、CID、fork 关系或 shared-object 授权。

### 3.2 安全影响

在未来多 CID 场景中，恶意 Linux 可能把受害 CID 的 private PFN 安装到另一个
protected root。QEMU 会把另一个 protected U-mode 也视为合法
`PRIVATE_DATA` 访问者，因为最终物理检查没有 PFN owner。

即使当前只有单 CID，只要同 CID 下有多个进程且目标语义仍是“默认不共享，
fork/显式 shared 才是例外”，Linux 仍可能把进程 A 的普通 private PFN 安装给
进程 B。这会破坏进程级默认隔离，并可形成间接泄漏或 mapping-confusion Iago
Attack。

### 3.3 本轮不预设的解决方式

这一问题不等价于“必须给所有 PFN 保存完整 64-bit ownerCID”。可能的安全
边界包括：普通路径只允许首次 `NORMAL -> PRIVATE_DATA`，已有 private PFN 的
新增映射全部通过 fork/COW/shared 等 typed operation；或者未来使用 compact
owner/group metadata。具体选择留待后续设计。

## 4. 缺口二：ptep_pa 未与 root + VA 重新绑定

### 4.1 当前实现

`sm_nacc_set_ptes()`、`sm_nacc_wrprotect_ptes()` 和
`sm_nacc_update_pte()` 分别接受：

```text
ptep_pa
start_va
root_pgd_pa
```

当前主要验证 `ptep_pa` 是否位于 Secure PTP region，或者是否是允许修改的
`ROOT_L0` slot。`nacc_semantic_prepare_pte_update()` 会验证传入
`root_pgd_pa` 对应一个记录过 CID 的 root，但普通 PTE 路径没有由 Monitor
重新执行 `walk(root_pgd_pa, start_va)` 并证明结果就是传入的 `ptep_pa`。

### 4.2 安全影响

恶意 Linux 可以提供一个合法 attached root 作为 semantic/private 判断上下文，
同时把另一个 Secure PTP 中的 slot 作为 `ptep_pa`。这会使 root/CID/VA 检查与
实际被修改的 PTE 分离。

该问题与 shared memory 无关，也与当前是否只有一个 CID 无关。它影响普通
page fault、权限变化、unmap、fork 和其他所有使用通用 secure-PTE ecall 的
路径。

## 5. 缺口三：裸 PFN acquire/retire ecall 仍对 Linux 暴露

### 5.1 当前实现

`sbi_ecall_nacc_handler()` 仍公开：

```text
SBI_EXT_LINUX_ACQUIRE_PRIVATE_PFN
SBI_EXT_LINUX_RETIRE_PRIVATE_PFN
```

对应的 `sm_nacc_acquire_private_pfn()` 和
`sm_nacc_retire_private_pfn()` 只接收 PFN，不接收或验证 root、VA、PTE slot、
old PTE 或操作类型。Linux 中仍保留相应 wrapper；即使 honest-kernel 正常路径
没有调用这些 wrapper，恶意 Linux 仍可直接构造该 ecall。

`nacc_bitmap_retire_private_data()` 在 refcount 归零时直接把
`PRIVATE_DATA` 改为 `NORMAL`。

### 5.2 安全影响

若一个 live private PFN 的 refcount 为 1，恶意 Linux 可以直接请求 retire，
使 tag 在 PTE 仍然存在或数据仍未清零时回到 `NORMAL`。bitmap 数据面随后不再
阻止 Linux S-mode 访问该物理页。

因此，tag/refcount 变化不能继续作为一个由 Linux 直接指定 PFN 的独立 API；
它必须是经过验证的 PTE/lifecycle 事务的内部副作用。

## 6. 缺口四：ROOT_L0 tag/retire 生命周期可被错误调用

### 6.1 当前实现

`SBI_EXT_LINUX_TAG_ROOT` 和 `SBI_EXT_LINUX_RETIRE_ROOT` 仍由 Linux 直接发起。

`nacc_bitmap_tag_root_l0()` 对已有 record 重新写入：

```text
record->cid = cid
record->flags = 0
```

因此重复 TAG_ROOT 会清除 `NACC_ROOT_RECORD_ATTACHED`。当前
`sm_nacc_retire_root()` 也没有证明 root 已经完成 detach、PTE 清理和 TLB
失效，就直接删除 semantic/root record并把 root PFN恢复为 `NORMAL`。

### 6.2 安全影响

- 重复 TAG_ROOT 可使 active root 丢失 attached 状态，后续 ordinary leaf 若
  同时省略 `PTE_NACC`，就可能绕过 attached-root 默认 private 分类。
- 提前 RETIRE_ROOT 可取消 ROOT_L0 的硬件写保护，使 Linux 重新直接修改仍在
  使用的 root page。
- 这些调用均可由恶意 Linux主动触发，不依赖正常内核生命周期是否会这样做。

## 7. 缺口五：最后引用回收尚未完成可信发布事务

当前 `nacc_bitmap_retire_private_data()` 在最后一个 ref 消失时把 tag 改回
`NORMAL`，但该函数本身不完成以下证明和动作：

1. 所有对应 PTE 已经由可信代码撤销；
2. 所有 hart/ASID/MMUIdx 中的旧翻译已不可继续使用；
3. 不存在未记录 alias；
4. 页面已经由 M-mode 可信清零；
5. 只有完成以上步骤后才向 Linux 发布为 `NORMAL`。

当前 QEMU 已对 tag 变化实现 PFN 定向 TLB/TB invalidation，但这不能代替
OpenSBI 对“最后一个合法映射确实消失”和“公开以前已经清零”的事务验证。

安全失败策略应当是保持 private/pending 并造成泄漏或 DoS，而不是在状态不明
时恢复 `NORMAL`。

## 8. 对当前安全结论的影响

当前 workload 与严格 raw-deny 回归证明的是 honest-kernel 功能路径能够工作，
以及 Linux S-mode 对稳定 `PRIVATE_DATA` 的直接访问会被硬件拒绝。它们没有
覆盖恶意 Linux 主动构造 ecall 参数、重复 root lifecycle 调用、伪造
root/ptep 组合或提前 retire PFN。

因此，当前适合采用的表述是：

> bitmap 数据面机制有效，但 OpenSBI 控制面尚未把 PTE slot、root、VA、
> PFN、授权来源和回收生命周期绑定为不可伪造的事务。当前实现尚不能宣称对
> 完全恶意 Linux 的普通 private memory 已经完整闭合。

这不要求推翻 bitmap，也不必立即引入大规模 per-PFN ownerCID。首先需要收紧
现有 Monitor API 和状态转换，使 Linux 只能提出请求，不能直接决定 tag、
refcount 或 root 生命周期。

## 9. 后续修复必须满足的约束

本文不决定具体代码方案，但后续修复至少需要满足：

1. Monitor 对每个普通 PTE 操作重新验证
   `walk(root_pgd_pa, va) == ptep_pa`，并验证 root 处于正确生命周期。
2. Linux 不再拥有裸 PFN acquire/retire 能力；private tag/refcount 只能随经过
   验证的 PTE commit/rollback 更新。
3. 普通路径不得自由增加已有 `PRIVATE_DATA` PFN 的 mapping；fork、COW、
   verified immutable mapping 和显式 shared 必须使用可识别的 typed 语义。
4. TAG_ROOT 对同一 root/CID 必须幂等且不能清除 active attached 状态；
   RETIRE_ROOT 必须证明 root 已退出并完成相关清理。
5. last-ref reclaim 必须按“撤销可达性、同步翻译、可信清零、最后发布
   `NORMAL`”的顺序执行，并在失败时 fail closed。
6. 当前若继续限定单 CID，需要在威胁模型和论文表述中明确；该限定不能替代
   同 CID 默认不共享和 Monitor 控制面验证。

## 10. 与 shared-memory 讨论的关系

shared memory 会主动允许一个 PFN 存在多个合法 root/VA mapping，因此需要比
ordinary private 更明确的 object、generation、mapping-set 和 lifecycle
metadata。但 shared 方案不应被用来掩盖本文列出的普通 private 控制面问题。

后续讨论 Agent-managed shared memory 时，应把本文约束视为共同基础：

- Linux 可以提供 VMA/VA compatibility 服务，但不能成为 PFN、PTE 或 object
  lifetime 的安全 authority；
- Agent 可以保存 shared-object 授权 metadata；
- OpenSBI 必须最终验证和执行 PTE/tag/lifecycle 转换；
- shared pool 的普通 PTE 入口必须与 ordinary private 路径明确分流。

具体是否绕过 Linux `acall/aret`、是否保留 opaque VMA、如何支持 fault、fork、
exit 和 futex，留待下一轮讨论，不在本文预设结论。
