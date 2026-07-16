# NaCC 多 CID 隔离与跨容器共享内存讨论记录

日期：2026-07-14

状态：问题定义和初步方向讨论，不是已冻结的实现方案。本文基于当前代码和已经
确定的同 CID Agent-direct SysV SHM基线，梳理多容器以后必须新增的安全语义、可
复用部分、候选方案和优先讨论的问题。本文不表示当前代码已经实现安全的多 CID
隔离或跨 CID共享。

相关记录：

- `20260714_nacc_agent_direct_shared_memory_design_baseline.md`：同 CID多进程
  Agent-direct SysV SHM基线；
- `20260713_nacc_bitmap_control_plane_security_gaps.md`：普通 private page的 PTE、
  root、PFN和生命周期控制面缺口；
- `20260713_nacc_agent_pool_bitmap_shared_memory_plan.md`：Agent-managed shared
  physical pool和 bitmap布局讨论。

## 1. 本轮需要区分的三个问题

多容器问题不能只写成“给 bitmap加 CID”。至少需要区分：

1. **普通 private page的跨 CID隔离**

   容器 A的普通 private PFN不能被 Linux映射到容器 B的任意 root。fork/COW只在
   已验证的同 CID父子关系中增加映射。

2. **每个 CID内部的显式共享**

   这一部分沿用已经确定的 Agent-direct SysV SHM：默认 namespace是
   `(CID, key)`，同 CID trusted process通过 `shmget/shmat`取得同一对象。

3. **不同 CID之间的显式共享**

   默认仍然不共享。只有被可信策略明确放入同一个 sharing domain的容器，才能
   attach指定 shared object。相同整数 key、相同 Linux IPC namespace或 Linux
   提供的 handle都不能自动构成跨 CID授权。

先实现第 1 点是第 3 点的前提。否则“跨 CID共享”只是允许一个当前已经能够被
Linux任意制造的 cross-root mapping，并不能形成安全例外。

## 2. 当前代码已经具有的多 CID骨架

### 2.1 `nacc_state`已经携带 CID

`opensbi/include/sm/nacc.h`把 `nacc_state`划分为：

```text
48-bit CID | 2-bit state | reserved bits
```

OpenSBI的 per-thread context load会恢复对应 CID和 Agent/Linux state。因此，从
“当前执行上下文属于哪个 CID”这个角度看，硬件模型已经有可用字段，首版多 CID
设计没有明显理由再增加一个 CID CSR。

但“寄存器里有 CID”不等于“CID来源可信”。这一点见第 3 节。

### 2.2 OpenSBI已有 container、process和 root记录

当前代码已经维护：

- `nacc_container_t { cid, process list }`；
- `PID -> CID` hash entry；
- `root_pfn -> { cid, attached }` root record；
- `MAX_CONTAINER=32`、`MAX_PROCESS=32`的原型上限。

invoke、fork-child attach和 thread context路径已经尝试通过 PID表取得 CID，并把
root与 CID关联。这些结构可以作为未来 trusted domain registry的起点。

### 2.3 bitmap最终访问判断不区分 CID

QEMU当前对 `PRIVATE_DATA`的最终访问条件是：

```text
M-mode
or NACC_STATE_AGENT && (U-mode or S-mode)
```

该判断不读取 `nacc_state`中的 CID，也没有 PFN owner/group字段。因此一旦容器 A
的 private PFN被错误安装到容器 B的 protected root，QEMU会允许 B的 protected
U-mode访问。bitmap当前表达的是：

> Linux/ordinary context不能访问该页，但受保护世界中的哪个 CID可以访问并未
> 由 bitmap表达。

### 2.4 private refcount不等于 owner

现有每 PFN `u32` private refcount只能回答当前有多少受保护映射引用，不能回答：

- 第一次映射属于哪个 CID；
- 新增 mapping是否仍在同一个 CID；
- 多个 mapping来自 fork、COW还是显式 shared；
- refcount归零前后是否允许 CID复用。

`nacc_prepare_secure_pte_update_for()`当前会对 attached root中的 ordinary leaf获取
private refcount，但没有把 `new_pfn`与 root CID的可信 owner绑定。这是多 CID前
必须修复的核心路径。

### 2.5 当前 CID mapping扫描不是 owner机制

`nacc_bitmap_cid_maps_private_data()`会扫描指定 CID的 attached roots，判断某个 PFN
是否已经出现在其中；当前主要用于 private-data uaccess授权。

这个扫描可以证明“现在至少有一张该 CID页表映射了PFN”，但不能证明该映射最初
是否合法，也不能在零映射期间保存 owner。若恶意 Linux已经诱导错误 PTE进入该
CID，扫描反而会把错误结果当成事实。因此它不能作为多 CID owner authority。

## 3. 当前最先需要修正的是 CID 身份来源

当前 `nacc_register(cid)`直接接收调用参数，Linux把该 CID写入
`current->thread.nacc_cid`并传给 OpenSBI；`sm_nacc_register()`随后按这个值创建或
查找 container record。

在只运行一个实验容器时，这可以作为功能标识。但在恶意 Linux和多个互不相同
安全域的模型中，仅凭裸整数 CID加入已有 container是不够的：

```text
malicious Linux chooses victim CID
    -> registers an attacker process under that number
    -> obtains root/thread context carrying victim CID
    -> all later "same CID" checks lose meaning
```

因此，多 CID安全模型首先需要一个可信的 **domain handle生命周期**：

1. container首次创建时，由 Agent/OpenSBI确认创建事件并分配或认证 domain handle；
2. fork继承父 domain，不重新接受 Linux指定的裸 CID；
3. 独立进程加入已有 container时，必须经过可信 launch/manifest关系，而不是知道
   一个 CID数字即可加入；
4. root、thread context和 Agent metadata都绑定同一个 domain handle；
5. container teardown后旧 handle不能在新 container中静默复用。

现有48位 CID字段足以编码 slot与 generation，因此这个问题原则上不要求新 CSR。
具体由谁触发 container create、怎样验证独立 exec image属于该 container，仍需
单独讨论。

## 4. 普通 private page 跨 CID隔离的候选方法

### 4.1 方法 A：硬件最终访问时比较 PFN owner CID

为每个 private PFN保存 owner/group，并让硬件在每次访问时比较
`PFN.owner == nacc_state.cid`。

优点：

- 即使错误 PTE进入另一 CID，最终物理访问仍被拒绝；
- 安全结论直观。

代价：

- bitmap不再是简单2-bit tag，需要额外 owner metadata和硬件访问；
- shared page需要单 owner以外的 group/participant表达；
- owner lookup进入每次物理访问路径；
- QEMU可以模拟，但硬件故事、metadata cache和并发更新明显变重。

这一方法最强，但与当前希望避免扩大硬件改动的方向不一致，不宜作为默认首选。

### 4.2 方法 B：Monitor软件 owner + 安全页表作为访问能力

bitmap继续只区分 `NORMAL/PEND/PRIVATE_DATA`。OpenSBI为 ordinary private PFN维护
可信 owner domain，并在所有 PTE提交时检查：

```text
first NORMAL/PEND -> PRIVATE_DATA mapping
    -> bind PFN owner_domain = current root domain

new ordinary mapping of an existing PRIVATE_DATA PFN
    -> require target root domain == owner_domain
    -> and require a typed fork/COW/verified alias operation

explicit shared-pool PFN
    -> reject ordinary path
    -> only Agent-authenticated shared-object path may map it

last trusted private reference disappears
    -> revoke PTE reachability
    -> synchronize TLB
    -> trusted-zero
    -> clear owner and publish/reclaim
```

该方法不在每次 load/store比较 CID。它依赖如下闭环：

- Linux不能直接写 secure page tables；
- Monitor重新 walk真实 `root + VA`，而不是信任裸 `ptep_pa`；
- 每个 root有不可伪造且不可中途改变的 domain handle；
- 没有裸 PFN acquire/retire旁路；
- ASID/root切换和 TLB失效不能保留跨 domain旧翻译。

在这些条件成立时，PTE本身就是受Monitor签发的访问能力。普通硬件页表隔离也不是
在每次DRAM访问时查询“进程owner”，而是依赖页表只产生被授权的翻译。NaCC可以
沿用这一思路：bitmap负责把Linux排除在受保护世界外，Monitor页表控制负责区分
受保护世界内部的 CID。

这是本文当前最倾向继续研究的方向。

### 4.3 owner metadata不一定是完整48-bit数组

方法 B仍需要某种 owner事实，但不必把48-bit裸 CID塞进硬件 bitmap。候选包括：

- 为每个 tracked PFN增加16/32-bit `domain_slot + generation`软件表；
- 只为 live private PFN建立 sparse owner record；
- 给每个 CID分配若干物理 extent，由 PFN extent反推出 owner；
- dense owner表与 sparse exception表组合。

当前 ordinary private refcount arena本身已经为约一百万个4 KiB页面保留约4 MiB。
若使用 compact domain slot，额外软件 metadata是 MiB级问题，而不是每次硬件访问
都携带48-bit owner的问题。真正需要权衡的是：

- dense表简单、O(1)，但固定占用；
- sparse表节省空闲页开销，但查找、并发和耗尽处理更复杂；
- per-CID extent最容易讲，但产生碎片、配额和动态回收问题。

这里尚未选择具体表示。

### 4.4 方法 C：静态 per-CID private pool

为每个 CID预留独立物理范围，普通 PTE路径只允许映射本 CID范围；另设全局
Agent-managed shared pool。

这对学术原型最容易验证，也不需要逐页 owner lookup。但固定32个容器时会出现
明显碎片和不均衡，容器创建/销毁后的动态复用仍需要可信 extent生命周期。它可以
作为早期对照实现，但未必适合最终设计。

## 5. 同 CID SysV SHM 可以直接复用的部分

同 CID设计已经提供跨容器方案所需的大部分对象机制：

- Agent-private shared allocator；
- key、shmid、object和 attachment记录；
- shared pool与 ordinary private PFN范围分流；
- Agent-direct `shmget/shmat/shmdt/shmctl`；
- OpenSBI typed attach/detach；
- fork/exec/exit和 `IPC_RMID`生命周期；
- PTE撤销、TLB同步和 final trusted zero。

多 CID以后，默认行为仍应是：

```text
container A: (A-local IPC namespace, key K) -> object A.K
container B: (B-local IPC namespace, key K) -> object B.K

object A.K != object B.K
```

因此，同一个整数 key绝不能默认造成跨 CID共享。现有 `(CID, key)` namespace正好
提供默认隔离。

## 6. 跨容器共享的初步抽象：trusted IPC sharing domain

为了保持应用继续使用原生 `shmget/shmat`，一个较自然的候选是区分：

```text
memory domain handle (CID)
    -> ordinary private page隔离边界

IPC sharing domain / trusted IPC namespace
    -> 哪些 CID可以解析同一组 SysV SHM key/object
```

默认情况下，每个 CID拥有唯一 IPC namespace：

```text
ipc_namespace(CID_A) != ipc_namespace(CID_B)
```

需要跨容器共享时，由可信 container launch策略把若干 CID绑定到同一个 IPC sharing
domain。Agent把 `shmget(key)`解析为：

```text
(trusted_ipc_namespace, key) -> shared object
```

这样有几个好处：

1. User App仍使用原生 SysV SHM调用，不增加运行时 grant syscall；
2. Linux不能通过伪造相同 key建立跨容器关系；
3. ordinary private page仍按各自 CID隔离；
4. Agent可以从当前 root CID查 trusted IPC namespace，不接受应用或 Linux在每次
   `shmget`时指定目标 CID；
5. 不需要给每个 shared PFN增加硬件 owner CID，participant关系保存在 Agent
   object/namespace metadata中。

这与 Linux“不同容器默认拥有不同 IPC namespace、显式配置时共享 IPC namespace”
的应用直觉接近，但 authority从 Linux移到了 Agent/OpenSBI。

## 7. trusted IPC namespace 仍有两种不同安全语义

### 7.1 整组容器对该 namespace彼此信任

若加入同一 sharing domain的容器彼此信任，那么该 namespace中的任一应用可以按
SysV key查找对象，并按当前简化语义执行 `IPC_RMID`。这最接近同 CID方案，改动
最小，也不需要 per-object grant。

这种模型适合：

- 一组共同组成同一机密服务的sidecar/worker容器；
- 人为拆成多个container、但本来就属于同一信任域的应用；
- 首版跨容器共享原型。

### 7.2 容器彼此不信任，只共享少数对象

若 CID A和 CID B是不同安全主体，只允许访问某一个对象，那么“共享整个 IPC
namespace”过宽。至少需要可信地表达：

```text
shared object O
participants = {CID_A, CID_B}
rights = read-only / read-write / remove-policy
```

这个授权不能由 Linux提供。候选来源只有：

- container创建时经过完整性保护的静态 manifest；
- 已认证 owner container通过 Agent发起的 runtime grant；
- 更高层可信 orchestrator/attestation policy。

如果不希望引入 runtime grant，首版可以只支持静态 sharing manifest，或者明确
限定“加入同一 IPC sharing domain的容器彼此可信”。二者必须选择一个，不能一边
声称不同 CID互不信任，一边让所有同namespace容器按key访问和删除所有对象。

## 8. 初步倾向的跨 CID MVP

在尚未确定最终威胁模型前，本文的初步倾向是按以下顺序推进：

1. **先实现多 CID默认隔离，不实现跨 CID共享。**

   可信 domain handle、root绑定、ordinary private owner检查和 TLB边界先闭合。

2. **保持每 CID独立 SysV IPC namespace。**

   直接复用同 CID方案验证多个容器使用相同 key仍得到不同 object。

3. **跨 CID首版采用创建时固定的 trusted IPC sharing domain。**

   membership在 container运行期间不可动态修改；不增加 user-visible grant。

4. **首版只支持sharing-domain成员彼此信任。**

   它们仍与其他 CID隔离，但组内对 shared SysV object不做额外 ACL。

5. **若论文确实需要互不信任容器只共享单对象，再增加静态 per-object manifest。**

   不先实现动态 grant、revoke和复杂rights。

这一顺序最大限度复用同 CID SysV设计，也避免一开始同时解决身份、owner、ACL、
动态revocation和硬件owner检查。

## 9. Agent 与 OpenSBI 的职责扩展

### Agent

Agent继续作为全局可信 TCB，可以同时服务多个 CID，但所有可变状态必须显式带
domain handle：

- `domain_handle -> trusted IPC namespace`；
- `(ipc_namespace, key) -> shared object`；
- shared object participant/membership policy；
- `(root, VA) -> attachment`；
- namespace/object生命周期和 quota。

Agent private region可以被所有 protected root映射为无 `PTE_U`的同一可信 runtime；
不需要为每个 CID复制一份Agent。但 per-hart临时状态、缓存和错误回滚不能把前一个
CID的 object/root上下文带入下一个 CID。

### OpenSBI

OpenSBI负责：

- 创建、认证和回收 domain handle；
- root与 domain handle不可变绑定；
- ordinary private PFN owner检查；
- 只允许 authenticated Agent shared typed operation跨 owner建立映射；
- 验证 target root的真实 domain；
- PTE re-walk、tag事务、TLB同步和可信清零；
- container/namespace teardown时阻止 ID/PFN提前复用。

OpenSBI不必复制Agent的完整 SysV key表，但不能接受 Linux直接提交
`target_cid + pfn + va`就建立跨 CID映射。

## 10. TLB、ASID 与 CID 切换不能忽略

若bitmap不在每次访问时比较 CID，那么旧翻译的生命周期就是隔离边界的一部分。
多 CID至少要证明：

1. malicious Linux不能用同一 ASID/root identity保留另一 CID的旧 TLB translation；
2. root重新绑定或 CID handle复用前已经完成必要的 global/targeted fence；
3. shared object revoke、container exit和 namespace teardown清除了所有 participant
   root上的旧翻译；
4. QEMU MMUIdx优化不会把不同 root/CID的翻译错误复用。

这不意味着每次 Agent/Linux状态切换都全刷 TLB。目标应是把同步绑定到 PTE撤销、
root复用、ASID复用和 membership改变这些真实翻译生命周期事件，而不是绑定到
普通 syscall或每次 state切换。

## 11. 需要保持的安全不变量

1. 裸整数 CID、PID、Linux namespace ID和 SysV key都不能单独构成安全授权。
2. 一个 root在 live期间只能绑定一个不可改变的 domain handle。
3. ordinary private PFN只有一个 owner domain；同 CID fork/COW是typed alias例外。
4. ordinary PTE入口永远不能映射 shared-pool PFN。
5. shared PTE入口只接受 Agent-authenticated object attachment，不能接受 Linux
   指定participant。
6. 不同 CID使用相同 key默认得到不同 object。
7. 跨 CID共享必须来自可信 IPC namespace或 per-object policy。
8. CID/namespace/object ID复用必须带 generation或等价 stale-handle防护。
9. revoke先撤销所有 PTE和旧翻译，再删除participant或回收PFN。
10. 无法证明清理完成时保持 PRIVATE/PEND并泄漏，不向错误 CID或 Linux发布。

## 12. 当前不建议立即做的事情

- 不立即扩展bitmap bit宽度或增加每次访问的硬件owner比较；
- 不让Linux IPC namespace直接决定trusted IPC namespace；
- 不让所有 CID共享一个全局 `(key -> object)`表；
- 不用当前 root扫描结果替代PFN owner事实；
- 不同时实现动态join、runtime grant、partial revoke和per-object ACL；
- 不在普通private控制面尚有旁路时先开放跨CID shared mapping。

## 13. 后续需要逐项讨论的问题

以下问题尚未定案，建议一次只讨论一个：

1. 不同container中的 protected User App是否被视为互不信任的安全主体，还是只需
   对Linux隔离、sharing group内部应用彼此可信？
2. trusted domain handle由谁创建，独立进程如何在不信任Linux的情况下加入已有
   container？
3. ordinary private PFN owner使用dense compact table、sparse live table还是
   per-CID extent？
4. existing 48-bit CID如何编码 slot/generation，以及何时允许复用？
5. trusted IPC sharing domain是在launch时静态配置，还是需要运行时join/leave？
6. sharing domain共享整个SysV namespace，还是只共享manifest列出的key/object？
7. 一个participant能否执行 `IPC_RMID`，还是只有creator/owner可以删除？
8. 多CID下ASID由谁分配和验证，哪些事件必须执行targeted/global TLB fence？
9. container异常退出时，如何可信枚举root、ordinary owner page和shared attachment？
10. 论文首版是否只声明“多CID隔离 + 同CID共享”，把跨CID共享留为扩展？

## 14. 当前初步判断

多 CID并不必然要求给PMP增加新能力，也不必然要求硬件在每次物理访问时查询
ownerCID。现有 `nacc_state`已经携带 CID；只要 secure page-table更新路径真正闭合，
可以让bitmap继续负责“Linux versus protected world”，让Monitor签发的PTE负责
“protected domain A versus protected domain B”。这需要可信domain handle和
ordinary PFN owner metadata，但owner metadata可以是Monitor软件状态，而不是新的
硬件访问路径。

同 CID SysV SHM设计可以直接作为对象与生命周期底座。跨 CID共享最自然的首版
扩展不是全局key或Linux代理，而是Agent管理的trusted IPC sharing domain：默认
每 CID独立，只有创建时被可信策略放入同组的容器才解析同一组SysV对象。

当前最需要先回答的不是PFN表具体占几位，而是第13.1项：不同 CID之间到底是否
互不信任。这个答案决定“共享一个IPC namespace”是否已经足够，还是必须进一步
设计per-object participant和权限策略。
