# NaCC Agent-direct SysV SHM 同 CID 共享内存设计基线

日期：2026-07-14

状态：后续实现讨论的当前设计基线。本文固定首版共享内存的接口方向、信任边界、
物理与虚拟地址组织、对象生命周期和实现顺序。本文不代表代码已经实现，也不代表
已经支持完整 Linux System V IPC、POSIX SHM、futex、GUP、多 CID或恶意 DMA。

相关记录：

- `20260713_nacc_agent_pool_bitmap_shared_memory_plan.md`：shared physical pool、
  bitmap coverage和 Agent重定位分析；
- `20260713_nacc_bitmap_control_plane_security_gaps.md`：ordinary private bitmap
  控制面仍需收紧的安全缺口；
- `20260713_nacc_agent_managed_same_cid_shared_memory_open_questions.md`：此前方案
  演进和问题背景。

若上述旧记录中的 Agent fd、POSIX SHM或 `mmap(MAP_SHARED, handle)`结论与本文
冲突，以本文的 Agent-direct SysV SHM基线为准；旧内容只保留为设计演进记录。

## 1. 目标与范围

NaCC已有语义是：普通 User App数据页默认 private；除 fork/COW等有明确语义的
路径外，Linux不能把一个受保护页任意增加到其他 root。现在需要增加一个低频、
显式、同 CID多进程共享的例外，同时保持以下原则：

1. 共享由 Agent直接管理，不让 Linux成为 object、PFN、PTE或生命周期 authority。
2. 共享操作不经过 `acall -> Linux -> aret`代理；Agent完成后直接返回 U-mode。
3. 使用已有 bitmap数据面阻止 Linux访问，不增加 bitmap bit、CSR或 PMP语义。
4. 使用 Linux原生、意图明确的 System V SHM syscall ABI，避免自定义应用接口，
   也避免把 POSIX SHM的 VFS/fd调用序列翻译成 Agent对象操作。
5. 首版只解决同 CID、经过初始 ELF完整性验证且彼此可信的 User App之间共享。
6. 首版对象是 Agent-managed volatile memory segment，不是文件，不持久化，也不
   进入 Linux VFS、tmpfs、shmem inode或 page cache。

本文所说“Linux不参与”是指：受保护进程的 `shmget/shmat/shmdt/shmctl`不会委托
Linux，Linux不保存 per-object可信状态。初始化时保留一个粗粒度 opaque VMA，
使 honest Linux的地址分配器避开 NACC固定窗口，仍然可以作为兼容措施；该 VMA
不是安全依据，也不要求随每次 attach/detach变化。

## 2. 已固定的核心决策

1. 普通应用页默认 private；显式 SysV SHM是独立 typed语义，不能把任意 private
   PFN隐式升级为 shared。
2. 受保护进程使用原生 `shmget`、`shmat`、`shmdt`和
   `shmctl(IPC_RMID)`进入 Agent。
3. Agent不把这些调用翻译成 Linux `mmap`、`open`或其他系统调用；Linux的 SysV
   IPC表中不创建对应对象。
4. `shmid`由 Agent生成、解释和校验，按 CID隔离；Linux不能生成、替换或解析
   一个可信 `shmid`。
5. Agent维护 `(CID, key) -> shared object`、`shmid -> shared object`和
   `(root, VA) -> attachment`三类可信关系。
6. 同 CID trusted User App不增加 grant或 ACL。知道 key的进程可通过 `shmget`
   取得同一对象的 `shmid`，但 Agent仍验证调用者属于已登记的 protected root。
7. shared physical page来自固定 Agent-managed shared pool。
8. shared object存活期间，其 PFN保持 `PRIVATE_DATA`；free、创建中或销毁中的 pool
   页面保持 PEND，永不作为 ordinary Linux RAM发布。
9. bitmap只表达最终物理访问类别，不表达 object、root、CID、key或 attachment。
10. Agent是 policy authority，维护 key namespace、shmid表、object、allocator、
    attachment和生命周期状态。
11. OpenSBI是 enforcement authority，认证 Agent调用，验证 root/VA/PFN/PTE，
    执行可信清零、tag转换、PTE提交和跨 hart TLB同步。
12. fixed shared VA window从现有 1 GiB NACC地址槽中划分；精确偏移与大小可以在
    实现前决定，不改变接口和安全模型。
13. MVP优先使用 eager object allocation和 eager PTE installation，不把共享
    page fault重新交给 Linux。
14. `IPC_RMID`删除 key可查找性并把对象标记为待销毁；已有 attachment继续有效，
    最后一次 detach后由 Agent可信清零并回收。
15. 不支持的 SysV SHM操作必须由 Agent明确返回错误，不能回落到 Linux，从而避免
    同一受保护进程同时出现 Agent对象和 Linux对象两个不一致的 IPC namespace。

## 3. 为什么首版采用 SysV SHM

### 3.1 SysV路径直接表达共享意图

在 RISC-V Linux ABI上，目标调用可以作为独立 syscall被 Agent识别：

```text
shmget(key, size, flags)       -> Agent object lookup/create，返回 Agent shmid
shmat(shmid, addr, flags)      -> Agent attachment，返回 shared VA
shmdt(addr)                    -> Agent detach
shmctl(shmid, IPC_RMID, NULL)  -> Agent mark-for-removal
```

当前仓库的 asm-generic ABI分别定义 `__NR_shmget=194`、`__NR_shmctl=195`、
`__NR_shmat=196`和 `__NR_shmdt=197`。实现应从共同 ABI定义取得这些值，避免 Agent
与 Linux分别维护容易漂移的手写 syscall number。

Agent只需要解码 ABI并执行对应对象操作，不需要再构造 Linux syscall，也不需要
引入 NaCC专用 `nacc_shared_*`应用接口。原本使用这一 SysV SHM子集的程序可以保持
源码和调用序列不变。

### 3.2 POSIX SHM会重新引入非核心复杂度

Linux上的 `shm_open`不是一个独立内核 syscall。现有 libc通常把它展开为
`/dev/shm`上的 open类调用，再组合 `ftruncate`、`mmap`、`close`和 `unlink`。
若 Agent要在不依赖 Linux VFS的前提下无修改接管，就必须额外模拟：

- 路径识别和 namespace；
- Agent fd与 Linux fd编号共存；
- `ftruncate`与对象 size的跨 syscall关联；
- `mmap(fd)`识别、`close`、`dup`和 close-on-exec；
- `shm_unlink`与 descriptor/mapping分离的生命周期。

这些工作不会加强 bitmap或 PTE安全，只会扩大兼容层。因而 POSIX SHM不再是
首版既定目标；未来只有在 workload明确要求时，才评估是否在稳定 SysV核心之外
增加适配层。

### 3.3 采用 SysV仍不意味着复用 Linux实现

Linux内部可以使用 shmem file等机制实现 SysV SHM，但这不是 syscall ABI的必要
组成。NaCC只复用应用可见 ABI和基本生命周期，不复用 Linux的 IPC对象、VFS、
页分配器、VMA authority或 page fault路径。

## 4. 信任与强制分层

### 4.1 数据面：bitmap

```text
ordinary private live page    -> PRIVATE_DATA
shared object published pages -> PRIVATE_DATA
shared unallocated/reserved/reclaimed pages -> PRIVATE_COPY_PENDING / PEND
ordinary Linux page           -> NORMAL
```

创建事务中的页面在可信清零前保持 PEND；清零并转换完成后，即使 object仍处于
`CREATING`且尚未对 key/shmid可见，其页面也已经是 `PRIVATE_DATA`。销毁事务先撤销
全部 PTE和旧翻译，再把页面转回 PEND并清零。

`PRIVATE_DATA`只回答“Linux是否可以在最终物理访问时读取或写入该页”。它不表示
single-owner，也不表示 shared。ordinary private与 explicit shared由固定 PFN范围
和可信 typed operation区分。

### 4.2 策略面：Agent

Agent决定并记录：

- `(CID, key)`是否绑定一个 live object；
- 一个 Agent `shmid`当前指向哪个 object；
- object由哪些 shared-pool PFN组成；
- 当前 root中有哪些 attachment及其 VA、长度和权限；
- object是否允许新 attach；
- object何时进入 `RMID_PENDING`和 final destroy。

同 CID User App彼此可信，表示不增加 user-to-user grant或权限 ACL；这不代表 Agent
跳过内存安全检查。所有 size计算、flags、VA范围、root身份、object状态和资源上限
仍必须验证。

### 4.3 强制面：OpenSBI

OpenSBI只接受语义明确的 shared typed operation，例如：

```text
SHARED_OBJECT_ALLOCATE_AND_ZERO
SHARED_ATTACH_CURRENT_ROOT
SHARED_DETACH_CURRENT_ROOT
SHARED_OBJECT_DESTROY
SHARED_FORK_INHERIT
SHARED_ROOT_TEARDOWN
```

具体 ecall编号和批量格式尚未确定，但不能复用允许任意 `va/pa/size/perm` 的宽泛
Agent mmap接口。OpenSBI不重复维护完整 key/shmid namespace，却必须验证本次操作
与当前 Agent state、attached root、fixed shared window和 shared PFN范围一致。

### 4.4 Linux只保留兼容性角色

Linux可以在 protected mm初始化时保留整个 fixed NACC slot，使正常 ELF、brk和
mmap分配器避开该区间。此后：

- Linux不知道 segment边界、key、shmid、PFN或 attachment；
- `shmget/shmat/shmdt/shmctl`不进入 Linux；
- broad placeholder VMA不随 attach/detach更新；
- Linux伪造或删除 VMA metadata不能授予 shared PFN访问权；
- 恶意 Linux仍可能制造调度失败、地址空间冲突等 DoS，此类可用性攻击不作为
  confidentiality/integrity安全依据。

Monitor必须独立保护 fixed slot中的 PTE更新。不能把 `VM_NACC` flag本身当作恶意
Linux无法伪造的安全事实。

## 5. 物理布局

采用前置 shared pool、后置 Agent private region的计划布局：

```text
0x180000000 - 0x190000000  Agent-managed shared pool，暂定 256 MiB
0x190000000 - 0x19ff00000  Agent code/runtime/heap/control metadata
0x19ff00000 - 0x1a0000000  immutable tail region
```

这是目标布局，不是当前代码事实。实现时需要同步完成：

1. `nacc_sagent`和 Agent image起点移动到 `0x190000000`；
2. shared pool位于 Agent base-and-bound之外，只由 bitmap数据面保护；
3. bitmap coverage覆盖到 `0x190000000`，ordinary private refcount coverage仍截止
   `0x180000000`；
4. shared object/attachment refs只进入 Agent metadata，不进入 ordinary private
   `u32` refcount arena；
5. OpenSBI在 Linux启动前把整个 pool初始化为 PEND并可信清零；
6. Linux启动配置继续预留完整物理区域，但该预留不构成安全依据。

256 MiB pool包含 65536个 4 KiB页面。全 pool allocation bitmap只需 8 KiB；
object、PFN extent和 attachment metadata按实际 live对象分配，不需要为 ordinary
RAM增加 ownerCID数组。

## 6. 虚拟地址布局

当前代码已经为 protected mm在用户地址空间高位保留一个完整 1 GiB固定 NACC
slot，并只在其中映射实际 Agent运行区。首版在该 slot内部划分：

```text
fixed NACC VA slot
+--------------------------------+
| Agent-managed shared U window  | PTE_U，可由被 attach的应用访问
+--------------------------------+
| Agent private/control mapping  | 无 PTE_U，User App不可访问
+--------------------------------+
| guard / future reserved        |
+--------------------------------+
```

共享物理池布局与 shared U window是两个独立概念：PFN来自
`0x180000000 - 0x190000000`，但 Agent可以把同一 PFN映射到不同 root中由它选择的
shared VA。无需要求 VA等于 PA。

首版规则：

1. Agent为 `shmat(NULL, ...)`从当前 root的 shared window分配 VA。
2. OpenSBI只允许 Agent-authenticated shared operation修改该 window中的 PTE。
3. ordinary Linux PTE入口和 ordinary private PTE入口都拒绝 shared-pool PFN及
   shared window PTE slot。
4. 不为每个 attachment建立 Linux VMA；existing broad placeholder只防止 honest
   Linux allocator发生普通冲突。
5. 首版 eager安装全部 PTE，因此 shared访问不应进入 Linux page fault handler。
6. Agent拦截对 shared window有影响的 `shmdt`；其他 `munmap/mprotect/mremap`
   若命中该 window则明确拒绝，不能委托 Linux改变可信映射。

shared window与 Agent private mapping的精确边界、guard大小和单 root分配算法属于
实现参数，不影响上述安全边界。

## 7. 首版 SysV SHM ABI子集

### 7.1 `shmget`

```text
int shmget(key_t key, size_t size, int shmflg)
```

Agent直接处理：

1. 验证当前调用来自已登记的 protected root并取得可信 CID。
2. `key == IPC_PRIVATE`时总是创建新 object。
3. 其他 key按 `(CID, key)`原子查找；`IPC_CREAT|IPC_EXCL`遵循 create冲突语义。
4. 新 object要求非零、页对齐后不溢出且不超过 MVP上限的 size。
5. 查找到已有 object时，不允许请求 size大于已有 segment；精确 errno在实现表中
   对齐 Linux常用语义。
6. MVP在创建时 eager分配全部 PFN、可信清零并置为 `PRIVATE_DATA`，但不建立任何
   root PTE。
7. 成功返回 Agent-owned `shmid`；失败使用原生 syscall负 errno返回约定。

permission mode不作为同 CID trusted app之间的安全 ACL。Agent可以保存最低限度的
mode信息供未来 `IPC_STAT`兼容，但首版安全性不依赖 Linux uid/gid或 mode。

### 7.2 `shmat`

```text
void *shmat(int shmid, const void *shmaddr, int shmflg)
```

MVP行为：

1. 验证 `shmid`属于当前 CID且 object处于 `LIVE`。
2. 首版要求 `shmaddr == NULL`，由 Agent在 fixed shared window选择 VA；显式地址、
   `SHM_RND`和 `SHM_REMAP`后续再评估。
3. 默认安装 `U+R+W+!X`；`SHM_RDONLY`安装 `U+R+!W+!X`。
4. `SHM_EXEC`、hugetlb及未知 flags直接拒绝。
5. Agent创建 attachment事务记录，OpenSBI验证空 PTE slot、shared PFN和当前 root，
   再安装整段 PTE并同步 TLB。
6. 成功后 Agent提交 attachment并返回 VA；失败必须清除部分 PTE并回滚 VA记录。

同一个 object可以被不同 root attach，也可以在同一 root形成多个独立 attachment；
每次调用都生成独立 `(root, base_va, object)`记录。

### 7.3 `shmdt`

```text
int shmdt(const void *shmaddr)
```

`shmaddr`必须精确匹配当前 root中一个 live attachment的起始 VA。首版不支持 partial
detach。Agent标记 attachment为 `REVOKING`，OpenSBI验证并清除完全相同的 PTE范围，
完成目标 root/VA的 TLB同步后，Agent才删除 attachment并减少 `mapping_count`。

detach本身不改变 object PFN的 `PRIVATE_DATA` tag。只要 object尚未进入 final
destroy，其数据在零 attachment时仍继续存在并可被后续 `shmat`重新映射。

### 7.4 `shmctl`

首版必须实现：

```text
shmctl(shmid, IPC_RMID, NULL)
```

Agent原子删除 `(CID, key)`的可查找 binding（若该对象不是 `IPC_PRIVATE`），并把
object从 `LIVE`转换为 `RMID_PENDING`：

- 已有 attachment继续有效；
- 对非 `IPC_PRIVATE`对象，相同 key之后可创建新 object；
- MVP拒绝对 `RMID_PENDING` object建立新的 `shmat`；
- 已有 attachment发生 fork继承仍然允许，因为它延续现有可达性而不是按 shmid
  创建新的显式 attach；
- `mapping_count`归零时进入 final destroy。

Linux允许的某些“marked-for-deletion后继续 attach”扩展不属于MVP。首版选择拒绝
新 attach，使生命周期和并发状态更容易闭合。

`IPC_STAT`可以作为第二个兼容子集加入，但需要 typed copy-out用户指针处理；
`IPC_SET`、`SHM_LOCK`和 `SHM_UNLOCK`首版明确拒绝。

### 7.5 `ftok`边界

`ftok()`是用户态库函数，不会直接进入 Agent。部分程序用 Linux `stat`返回的文件
元数据派生 key，恶意 Linux可能使两个进程得到不同 key或制造碰撞。首版验证程序
使用固定整数 key，不把 pathname-derived key完整性纳入安全声明。

由于当前同 CID应用彼此可信，`ftok`操纵不会形成跨安全主体授权，但可能造成对象
混淆或 DoS。若未来要求未修改、依赖 `ftok`的应用，则需单独决定可信 key派生或
可接受的兼容边界；不能声称 SysV syscall接管已经自动解决该问题。

## 8. Agent metadata

Agent使用固定、所有 hart可访问的 Agent-private metadata arena，不直接依赖当前
只映射到单一 SATP且缺少并发保护的临时分配方式。

首版逻辑记录至少包括：

```text
shared_key_binding:
    cid
    key
    object_slot

shared_object:
    object_slot
    shmid                 Agent-visible integer ID
    reuse_generation      防止已回收 shmid误命中新 object
    cid
    key / IPC_PRIVATE
    state                 CREATING / LIVE / RMID_PENDING / DESTROYING
    size / page_count
    PFN list or extent list
    mapping_count

shared_attachment:
    object_slot
    root_pfn
    user_va
    length
    allowed_prot
    state                 INSTALLING / LIVE / REVOKING
```

`reuse_generation`只是 Agent内部实现原生整数 `shmid`的防复用字段，不是新的应用
grant或 object API。具体 bit编码尚未确定，但旧 `shmid`在对象槽复用后不能静默
命中新对象。

key表、object表、shared allocator和 attachment表必须由全局锁、分桶锁或等价
事务机制保护。两个 hart并发 `shmget(key, IPC_CREAT)`时只能有一个 object成为
该 key的可见结果；`IPC_EXCL`、attach、fork inheritance、detach与 final destroy
也必须在同一状态机下排序。只要 fork已经取得 object锁并开始继承，final destroy
就不能观察到虚假的零引用。

## 9. 对象与映射状态机

### 9.1 create

```text
Agent:
    authenticate current root/CID
    atomically resolve key and reserve object slot
    validate size/quota
    reserve PEND pages from shared allocator
    publish object only as CREATING

OpenSBI:
    authenticate Agent call
    validate every PFN is in shared pool and PEND
    trusted-zero every PFN
    transition PFNs to PRIVATE_DATA

Agent:
    commit key binding and object LIVE
    return shmid directly to U-mode
```

失败时页面只能回到无引用的 PEND，或保持 quarantined并泄漏；不能发布为 NORMAL，
也不能让半初始化 object通过 key/shmid可见。

### 9.2 attach

```text
Agent:
    validate current root/CID, shmid and object LIVE state
    reserve VA in current root shared window
    create INSTALLING attachment

OpenSBI:
    validate current root and exact VA slots
    validate object PFNs are shared-pool PRIVATE_DATA
    install U+R[/W]+!X PTEs
    perform required TLB synchronization

Agent:
    commit attachment LIVE
    increment mapping_count
    return VA directly to U-mode
```

目标进程必须自己调用 `shmat`。进程 A不能让 Linux代表进程 B安装映射；fork继承
使用独立 typed路径。

### 9.3 detach

```text
Agent:
    find exact current-root attachment by base VA
    mark it REVOKING

OpenSBI:
    re-walk current root and verify exact old PFNs/permissions
    clear the PTE range
    shoot down stale translations on relevant harts

Agent:
    remove attachment
    decrement mapping_count
    trigger destroy if object is RMID_PENDING and count reaches zero
```

### 9.4 `IPC_RMID`与 final destroy

```text
LIVE --IPC_RMID--> RMID_PENDING

RMID_PENDING with mapping_count > 0
    -> retain PRIVATE_DATA PFNs and existing attachments

RMID_PENDING with mapping_count == 0
    -> DESTROYING
    -> OpenSBI verifies no tracked PTE remains
    -> PFNs transition to PEND
    -> OpenSBI trusted-zeroes every PFN
    -> Agent returns PFNs to shared allocator
    -> advance reuse generation and release object slot
```

销毁后的 pool page保持 PEND，不返回 NORMAL，因此 Linux不能读取残留数据，也不能
把它作为 ordinary RAM复用。

## 10. Agent direct syscall路径

当前 Agent trap路径会保存原始 U-mode frame，然后把异常委托给 Linux。实现需要
增加只处理上述 SysV SHM syscall的 direct分支：

```text
protected U-mode ecall
    -> trap enters Agent
    -> Agent reads Agent-owned original user register frame
    -> dispatch shmget/shmat/shmdt/shmctl
    -> validate and update Agent policy metadata
    -> invoke typed OpenSBI enforcement operation when required
    -> write native syscall return value and advance user EPC
    -> restore Agent-owned frame and direct sret to U-mode
```

普通 syscall、interrupt和非 shared exception继续走现有 Linux代理路径。对于受保护
进程，一旦 syscall number属于 SysV SHM集合，Agent必须完整消费成功或错误结果，
不能在参数不支持时退回 Linux。

该接管只适用于已经登记的 protected root。普通非 NaCC进程仍由 Linux处理其
SysV IPC syscall，因而不会全局禁用或替换宿主 Linux的 System V IPC功能。

## 11. fork、clone、exec与exit

1. `fork`继承父 mm中的全部 SysV attachment，包括已经进入 `RMID_PENDING`对象的
   现有 attachment。Agent根据可信 parent/root关系为 child root安装同一 object
   PFN并建立 child attachment记录，不能只接受 Linux预植的任意 PTE。
2. `clone(CLONE_VM)`共享同一 mm/root时，不重复增加 attachment；metadata owner以
   mm/root为主，而不是按线程 PID计数。
3. 只有 `exec`成功替换旧 mm/image时才撤销旧 mm的全部 SysV attachment；失败的
   `execve`必须保留原映射。SysV `shmid`不是 fd，不存在 close-on-exec descriptor
   继承问题。
4. `exit`、异常退出和 root teardown按 root枚举并撤销全部 attachment。
5. object没有执行 `IPC_RMID`时，即使 `mapping_count == 0`也继续存在，符合 SysV
   segment持久到显式删除的基本语义。
6. 整个 CID teardown时，Agent把该 CID全部 object置为待删除，撤销残留 mapping，
   可信清零并回收全部 shared-pool PFN。
7. teardown证明不足或 TLB同步失败时保持 PRIVATE/PEND并泄漏，不能提前复用。

当前 root unregister路径尚未提供完整 shared cleanup；这是实现生命周期阶段的
必要工作，不应依赖 Linux单独发来的 PID或裸 PFN通知。

## 12. Iago防护与安全不变量

首版必须维持：

1. Linux不能通过返回值选择 key binding、shmid、PFN或 shared VA。
2. Agent只接受来自已登记 protected root的直接 U-mode syscall上下文；Linux
   S-mode不能伪造一个合法 User App shared操作。
3. ordinary PTE入口不能把 shared-pool PFN映射到任意 root；只有 authenticated
   shared typed operation能够建立重复映射。
4. OpenSBI根据真实 root和 VA重新 walk PTE slot，不信任 Agent或 Linux提供的裸
   `ptep_pa`。
5. shared attachment只允许出现在 fixed shared window，PTE始终 `U+R[/W]+!X`。
6. Agent metadata提交与 OpenSBI PTE/tag提交必须具有明确 rollback顺序。
7. detach后先完成 TLB shootdown，再减少最后 mapping引用。
8. final destroy先撤销全部可达性并可信清零，最后才回收为 PEND。
9. 不支持的 SysV flags和命令 fail closed，不委托 Linux创建同名替代对象。
10. bitmap负责阻断最终Linux访问，Agent metadata负责允许哪些重复映射；两者不能
    互相替代。

## 13. 实现阶段

### Phase 0：收紧共同控制面

- 完成 `root + VA + ptep`绑定验证；
- 封闭 Linux裸 PFN acquire/retire；
- 收紧 ROOT_L0 tag/retire生命周期；
- ordinary private入口拒绝已有 private PFN的非 typed新增映射；
- 完成 last-ref safe reclaim与可信清零顺序。

这些不是 shared特有工作，但若未完成，恶意 Linux仍可能绕过 Agent shared API。

### Phase 1：地址与直接 syscall骨架

- 固定 shared physical pool和 relocated Agent常量；
- 在现有 1 GiB NACC slot中定义 shared U window；
- 增加 Agent direct syscall识别、原生返回和错误返回路径；
- 对不支持的 SysV SHM命令禁止 Linux fallback。

### Phase 2：Agent object核心

- shared allocator和固定 metadata arena；
- `(CID, key)`表、Agent `shmid`表和 attachment表；
- 并发锁与 create/lookup/RMID状态机；
- eager object allocation、quota和 rollback。

### Phase 3：OpenSBI typed enforcement

- shared object allocate/zero；
- current-root attach/detach；
- exact PTE re-walk与 PFN范围验证；
- TLB同步和失败隔离；
- final destroy。

### Phase 4：进程生命周期

- fork继承；
- `CLONE_VM`去重；
- exec/exit/root teardown；
- CID teardown统一回收。

### Phase 5：兼容性扩展

在核心安全与状态机验证后，再按 workload决定是否加入：

- `IPC_STAT`；
- 显式 `shmaddr`与 `SHM_RND`；
- typed uaccess覆盖；
- process-shared futex；
- POSIX SHM兼容层。

Phase 5不是首版完成条件，也不能反向扩大 Phase 1-4的安全边界。

## 14. 验证计划

首版先使用固定整数 key和用户态原子/轮询，不依赖 `ftok`或 futex。

功能测试至少包括：

1. 两个独立同 CID进程分别 `shmget`同一 key并 `shmat`，互相观察读写结果；
2. `IPC_PRIVATE`每次创建不同 object；
3. `IPC_CREAT|IPC_EXCL`并发创建只有一个成功；
4. detach后重新 attach仍能读取对象数据；
5. `IPC_RMID`后旧 attachment继续可用、相同 key可创建新对象；
6. 最后一次 detach触发旧对象可信清零和回收；
7. stale `shmid`不能命中已复用 object slot；
8. fork继承共享内容，exec/exit正确减少 attachment；
9. unsupported flags返回稳定 errno且 Linux IPC表中不出现替代对象。

安全负向测试至少包括：

1. Linux ordinary PTE路径尝试映射 shared-pool PFN必须失败；
2. normal U进程猜测 shmid不能 attach；
3. Linux伪造 root、VA、PFN或 PTE slot必须失败；
4. Linux删除 broad placeholder VMA不能获得物理页访问；
5. attach/detach中途失败后不存在半提交 user PTE；
6. TLB未完成同步时 object不得销毁或复用；
7. shared PFN在任何回收阶段都不能转成 NORMAL。

性能测量后置于正确性验证之后，至少区分：

- `shmget`创建与 lookup；
- 首次 `shmat`和重复 attach；
- `shmdt`；
- 两进程 cache-line ping-pong；
- 不同对象大小和进程数量下的吞吐与 TLB shootdown成本。

## 15. 首版明确不支持

- POSIX `shm_open/ftruncate/mmap/shm_unlink`无修改兼容；
- ordinary Linux file-backed或 anonymous `MAP_SHARED`接管；
- Linux SysV IPC namespace、uid/gid permission和完整 `ipc_perm`语义；
- `ftok` pathname完整性；
- process-shared futex和未修改 pthread process-shared mutex/condition；
- GUP、pinning、RDMA、direct I/O和 io_uring registered buffer；
- `mremap`、partial detach、任意 `mprotect`、`msync`和 `madvise`；
- per-object `/proc/maps`、core dump和完整 Linux memory accounting；
- swap、migration、THP/huge leaf；
- 多 CID共享、跨 CID ACL和恶意 DMA。

以上不支持项必须返回明确错误或被固定窗口规则阻断，不能静默委托 Linux后宣称
仍属于受保护共享路径。

## 16. 实现前仍需确定的参数

以下问题不改变“Agent-direct SysV SHM”的架构基线，但写代码前需要逐项定案：

1. shared U window在现有 1 GiB slot中的精确起止地址；
2. `shmid` slot/generation的整数编码和最大 object数；
3. 单 object、单 CID及整个 pool的 size/quota上限；
4. eager allocation与 PTE批量 ecall的最大粒度和中断延迟上限；
5. remote TLB shootdown使用现有 SBI RFENCE还是 Monitor内部机制；
6. `IPC_STAT`是否进入首版兼容验收；
7. `SHM_RDONLY`以外支持哪些 flags和精确 errno；
8. shared typed uaccess优先支持哪些 copy/get/put方向；
9. 是否以及何时支持 futex；
10. 未来 workload是否真的需要 POSIX SHM适配。

这些问题应一次解决一个并更新本文，但不再回到让 Linux决定 shared object、PFN、
PTE或生命周期的方案。

## 17. 当前结论

首版采用由 Agent直接实现的 System V SHM子集。应用使用 Linux原生
`shmget/shmat/shmdt/shmctl(IPC_RMID)` ABI，Agent直接维护 key、shmid、object、
PFN和 attachment，OpenSBI执行最终 PTE/tag/TLB强制，Linux只保留固定 NACC地址槽
的粗粒度兼容性占位，不参与单次共享操作。

该选择没有消除共享内存必需的 object、mapping和回收状态机，但删除了 POSIX
SHM所需的 VFS、fd、ftruncate、mmap和 unlink翻译层，使实现更接近 NaCC现有
Agent/Monitor信任结构，也更适合作为学术原型的首个闭合版本。
