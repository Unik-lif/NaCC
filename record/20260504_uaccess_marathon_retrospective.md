# T5.1 uaccess-loop 马拉松复盘：负向结论、实验现象与 Prompt 缺陷

记录日期：2026-05-04

范围：2026-05-03 到 2026-05-04 的 `fallback_scalar_usercopy` / RISC-V raw uaccess loop feasibility marathon。

相关入口：

- 原始人类任务种子：`record/user_copy_task_packet.md`
- 父任务：`docs/workflow/tasks/active/TASK_20260503_011553_marathon_user_copy.md`
- broad-eight 子任务：`docs/workflow/tasks/active/TASK_20260504_013106_uaccess_loop_broad_eight_current_tree_validation.md`
- 简短 closeout：`record/20260504_uaccess_loop_feasibility_closeout.md`

## 1. 核心结论

这次长期马拉松没有继续跑下去的必要。它已经给出了一个有价值的负向结论：

**`fallback_scalar_usercopy` / RISC-V uaccess-loop 是热点，但不是当前最适合作为主性能优化边界的目标。**

更具体地说：

- 这个 MEPC family 很热，能解释相当多 `GENERIC_UACCESS` / PRIVATE_DATA trap。
- 但它不是一个干净的安全语义边界。
- 简单 workload 中，active-wrapper 子集 recoverability 很好。
- 一旦进入更真实的 fork/exec/file/user-buffer workload，recoverability、direction、wrapper context、PFN ownership/range attribution 都开始碎裂。
- 后续继续 broad validation 大概率只会增加表格细节，而不会改变主要判断。

因此当前建议是：

- 不继续把 broad uaccess-loop mediation 作为主性能优化路线。
- 不从当前证据启动 broad `fallback_scalar_usercopy` portal prototype。
- 如果未来仍然想做 uaccess demo，只能把范围缩到：
  `active-wrapper=yes + direction known + bounded range known + PFN owner exact + cid_match=yes`。
- 这个窄 demo 只能叫 mechanism demo，不能承诺大性能收益。

## 2. 为什么这个结论重要

这个事情值得记录，因为它不是一个常规 Linux profiling 问题。

普通性能优化里，看到热点后通常可以：

- 找到热点函数；
- 找到主要调用者；
- 在热点处做 batching / caching / fast path；
- 让不能处理的边界情况 fallback。

但 NaCC 的 PRIVATE_DATA 场景不同。这里每一个 fallback 或 fast path 都是安全边界：

- 不能因为 MEPC 在 `fallback_scalar_usercopy` 就放行；
- 不能因为 caller 看起来是 `copy_to_user` 就解封页；
- 不能忽略 `direction_unknown`；
- 不能忽略 `PFN_OWNER_MISSING`；
- 不能把 range attribution 缺失当作普通 profiling 噪声；
- 不能让原始用户页变成 shared / unsealed / aliased。

所以这次实验实际上回答的是：

> 一个低层热点能不能同时成为性能优化边界和安全授权边界？

当前答案是：不能直接成为。至少 broad 版本不能。

## 3. 实验路线概览

这次路线大致经历了以下阶段。

### 3.1 先前乐观背景

5 月 2 日的 closeout 让 raw uaccess 看起来值得追：

- active raw-uaccess：`11,054 / 183,878 = 6.0%`
- `to_user`：`8,243 / 11,054 = 74.6%`
- immediate caller 分散，但低层 raw uaccess abstraction 统一。
- 旧的 broader current-tree closeout 里，`GENERIC_UACCESS = 115,332 / 182,586 = 63.2%`。

当时的自然想法是：

> 如果 active raw-uaccess 子集只有 6%，但 broad MEPC-family 有 63%，那么真正的大目标可能不是 syscall 63 或 `copy_page_to_iter`，而是底层 `fallback_scalar_usercopy` loop 本身。

这个想法合理，但后来证明过于乐观。

### 3.2 第一轮 instrumentation：证明 active-wrapper 子集可恢复

Linux/OpenSBI 增加了 reporting-only instrumentation：

- Linux raw uaccess wrapper 记录 direction、user/kernel base、length、caller。
- Linux 报告 raw-copy loop bounds。
- OpenSBI 在 PRIVATE_DATA trap 时记录 MEPC、wrapper state、direction、range、PFN owner/origin、cid/root/task 等信息。
- 输出 marker，例如：
  - `[NACC][uaccess-static]`
  - `[NACC][uaccess-state-summary]`
  - `[NACC][uaccess-denominator-reconcile]`
  - `[NACC][uaccess-loop-hotspot]`
  - `[NACC][uaccess-pfn-owner]`

这一步是成功的。它证明 instrumentation 本身是有能力观察这一层的。

### 3.3 修复 denominator：从 active subset 走向 loop-MEPC denominator

最初 broad denominator 不够精确，后来修复了 loop denominator reporting。

T0 / workload 2 得到了很干净的结果：

- `loop_mepc=753`
- `active_wrapper_yes=753`
- `active_wrapper_no=0`
- `recoverable=720`
- `unrecoverable=33`
- `direction_from_user=194`
- `direction_to_user=559`
- `direction_unknown=0`
- `recoverable_over_broad_bp=9561`

这个结果非常漂亮：

- recoverable 占 `720 / 753 = 95.6%`
- 没有 inactive/no-wrapper loop rows
- direction 全部明确
- 只有 33 个 PFN-owner missing

如果只看这个 workload，会误以为 broad mediation 很有希望。

### 3.4 workload 6 暴露关键负向信号

workload 6：`wc -c /etc/hostname; echo done`

它 runtime 没失败，VM 输出正常，code 0。但它把 clean shape 打散了：

- `loop_mepc=3171`
- `active_wrapper_yes=2039`
- `active_wrapper_no=1132`
- `recoverable=1557`
- `unrecoverable=1614`
- `direction_unknown=1132`
- `UNRECOVERABLE_NO_WRAPPER_CONTEXT total=1132`
- `UNRECOVERABLE_EXCEPTION_FIXUP_CONTEXT total=64`
- `UNRECOVERABLE_PFN_OWNER_MISSING` 增长到 `482`

关键比例：

- 整体 recoverable：`1557 / 3171 = 49.1%`
- 整体 unrecoverable：`1614 / 3171 = 50.9%`
- no-wrapper：`1132 / 3171 = 35.7%`
- active-wrapper 内 owner-missing：`482 / 2039 = 23.6%`

这是整个 marathon 的转折点。

它说明：

- 不是 workload 挂了；
- 不是 logger 缺 marker；
- 不是 denominator 修错了；
- 而是 broad denominator 里真的混入了大量不适合 mediation 的状态。

### 3.5 source mapping：确认可疑 rows 不是日志幻觉

后续 mapping 证明 workload-6 的 no-wrapper rows 是真实 scalar-loop 指令：

- `ffffffff80a21842`：`fallback_scalar_usercopy` pre-alignment byte store
- `ffffffff80a218c2`：`fallback_scalar_usercopy` shift-copy word store
- `ffffffff80a218d6`：`fallback_scalar_usercopy` tail byte store

这些是 raw usercopy loop 内部真实 store 指令。

问题是它们没有 active wrapper context：

- direction unknown；
- 原始 user/kernel base 不可信；
- bounded range 不能恢复；
- 对 future mediation 来说必须 fail-closed。

同时，历史上看到的 `ffffffff80a20a02` family 被确认不是 raw uaccess loop：

- 它 map 到 `linux/arch/riscv/lib/clear_page.S:45`
- 是 `clear_page`
- 不是 `uaccess.S` exception-table fixup
- 不是 `fallback_scalar_usercopy`

这说明之前的 reporting 还把 active uaccess context 下的 nested/non-loop work 混进了 uaccess 解释里。

### 3.6 reporting repair：分类更清楚，但没有改变主结论

之后 OpenSBI reporting 被修正：

- inactive raw-loop denominator rows 明确保持 fail-closed；
- active-wrapper but non-loop MEPC 被单独标成 active-context non-loop；
- `[NACC][uaccess-loop-hotspot]` 不再承载非 loop 证据；
- 新增 summary 区分 aggregate total 和 retained marker sample。

这一步解决了“日志解释会误导”的问题。

但它没有把 broad target 变好。它只是证明：

- 之前看到的碎片不是都该算进可 mediate candidate；
- 当前 reporting 能更清楚地区分 candidate 和 non-candidate；
- 但 broad denominator 仍然不干净。

### 3.7 exec-stack / clear_page 诊断：继续证明边界效应复杂

为了复现 historical active-wrapper non-loop `clear_page` class，尝试过：

- exact workload retry；
- 16 次同类 amplification；
- 4 次 amplification；
- large environment stack-pressure；
- empty environment；
- 后续 Linux diagnostic around `binfmt_elf.c:220` / AT_RANDOM stack copy。

结论是：

- 这些尝试没有稳定复现 active-context non-loop OpenSBI trap；
- Linux 能观察到 active_uaccess=yes 下的 page zeroing；
- 但 source/log inspection 解释为：这是 pre-install anonymous page zeroing，页面还没作为 PRIVATE_DATA user mapping 安装，所以不会产生 OpenSBI-counted PRIVATE_DATA trap；
- 不是 OpenSBI classifier 漏掉了一个已发生的 non-loop trap。

这个过程有价值，但也说明路线已经进入边界效应追踪，而不是直接性能优化。

### 3.8 PFN owner / CID confidence：修好 reporting，但 482 仍然 fail-closed

PFN-owner confidence repair 后，workload 6 runtime proof 显示：

- `owner=PRIVATE_DATA total=2039`
- `owner=UNKNOWN total=482`
- `owner_missing_reason=root_absent total=0`
- `owner_missing_reason=range_absent total=482`
- `owner_missing_reason=ambiguous total=0`
- `origin_confidence=exact total=1557`
- `origin_confidence=missing total=482`
- `cid_match=yes total=2039`
- `cid_match=no total=0`
- `cid_match=unknown total=0`

这个结果有两面：

- 好消息：CID reporting 修好了，不再全是 unknown；
- 坏消息：482 个 owner-unknown 不是 root/cid 缺失，而是 range attribution absent。

这 482 个事件不能 mediate，只能 fail-closed。

## 4. 最终技术判断

### 4.1 broad uaccess-loop 不是好性能优化边界

`fallback_scalar_usercopy` 是热点，但它是很多语义路径汇聚后的低层实现。

它混合了：

- read/write user buffer；
- fork/exec stack setup；
- ELF auxv / random bytes；
- signal/stat 等 ABI copy；
- nested page fault / allocation effect；
- inactive raw-loop activity；
- active wrapper but out-of-range activity；
- PFN attribution incomplete activity。

这个层级太低，低到丢失了很多安全决策需要的语义。

### 4.2 clean subset 存在，但 payoff 口径不能扩大

可以安全讨论的 candidate 大概是：

- active wrapper；
- direction known；
- fault VA inside reported user range；
- original src/dst/len recoverable；
- PFN owner exact；
- cid match yes；
- bounded length。

这个子集是存在的，而且简单 workload 中效果很好。

但这已经不是 broad `GENERIC_UACCESS` portal，而是一个被严格过滤过的 mechanism demo 子集。

### 4.3 不应该把 MEPC family 当作 authority

这次实验反而强化了一个设计原则：

> MEPC 只能用于 reporting / candidate discovery，不能作为 policy authority。

因为同一个 MEPC family 下，不同 rows 的安全属性完全不同：

- 有的 recoverable；
- 有的 no wrapper；
- 有的 direction unknown；
- 有的 range absent；
- 有的是 non-loop work；
- 有的只是 active context correlation。

只看 MEPC 会非常危险。

## 5. 为什么马拉松没有收敛

### 5.1 任务把性能优化、可行性证明、语义测绘混在一起

原始任务同时要求：

- 找性能优化点；
- 证明安全可行性；
- 理解 RISC-V uaccess assembly；
- 记录 registers；
- 归因 PFN owner；
- 计算 recoverable coverage；
- 跑 workload；
- 给 prototype recommendation。

这些都合理，但放在一个 marathon DoD 里太大。

实际执行中，每次想回答“能不能优化”，都会被安全前提拉回去：

- direction 够不够？
- wrapper context 在不在？
- fault VA 是否在 range 内？
- PFN owner 是否 exact？
- cid 是否 match？
- 这个 MEPC 是不是 loop？
- clear_page 是不是 nested work？

于是性能优化任务逐渐变成了语义测绘任务。

### 5.2 目标选在了太底层的 implementation hotspot

`fallback_scalar_usercopy` 的问题是：

- 热；
- 集中；
- 但语义太底层。

它不是类似 “syscall X 的某个明确 buffer copy” 的边界，而是很多高层路径共享的实现细节。

底层热点适合 profiling，但不一定适合 confidential-container policy mediation。

### 5.3 缺少早停条件

原任务有很多 acceptance criteria，但缺少类似这样的早停规则：

- 如果第二个真实 workload 中 broad denominator recoverable 低于 60%，停止 broad portal；
- 如果 `active_wrapper_no` 超过 20%，停止 broad portal；
- 如果 PFN-owner missing 超过 10% 且原因是 range absent，停止 broad mediation；
- 如果为了复现一个 class 需要第三种以上 workload-shaping attempt，停止 runtime probing，转人工讨论。

没有这些早停条件后，marathon 会自然继续：

- 修一个 reporting gap；
- 跑一个小验证；
- 发现另一个 gap；
- 再修一个 summary；
- 再换一个 workload shape；
- 再追一个边界效应。

这就是复杂度越来越高、收益越来越低的根本原因。

### 5.4 "必须 fresh validation" 的规则让负向判断不容易落地

workflow 里为了避免旧日志误判，要求 fresh artifact。这是对的。

但在这个任务里，它也造成一个副作用：

- 已经有足够负向信号时，系统仍倾向于补更完整的 validation；
- broad-eight validation 被看成自然下一步；
- 即使实验现象已经说明主路线不乐观，packet 仍会继续要求 artifacts。

后面应该给 planner 一个明确权力：

> 当 fresh T0/T1 evidence 已经足以作出负向 feasibility decision 时，可以停止更大 validation，并记录 negative closeout。

### 5.5 role handoff 和 packet gate 放大了任务惯性

多角色流程本身能保证安全和可审计，但对这种探索型任务有惯性：

- coder 修 reporting；
- reviewer approve；
- test_runner validate；
- log_analyzer reduce；
- planner route next child。

这个循环很适合实现确定功能。

但对开放式性能调研，如果没有强 stop rule，它会持续把“下一个未知点”变成“下一个 child packet”。

这次就是这样：每一步都有合理性，但整体方向已经从“找优化点”变成“追完所有边界情况”。

## 6. Prompt / 任务设计缺陷

这次最值得反思的是 Prompt 设计。

### 6.1 Goal 太大

原目标问：

> Determine whether `fallback_scalar_usercopy` / `__asm_copy_*_user` can support a general, bounded, fail-closed mediation prototype.

这个目标本身包含：

- general；
- bounded；
- fail-closed；
- mediation；
- prototype feasibility；
- broad workload evidence。

其中每个词都可以展开成一个独立任务。

更好的方式应该拆成：

1. 静态 uaccess assembly/register model；
2. active-wrapper recoverability proof；
3. broad denominator quality check；
4. PFN-owner/range attribution quality check；
5. performance target decision；
6. only if positive: prototype packet。

### 6.2 Definition of Done 过于研究报告化

原 DoD 要求：

- static assembly summary；
- runtime state attribution；
- recoverability classification；
- denominator reconciliation；
- loop hotspot coverage；
- PFN owner validation；
- feasibility classification；
- prototype candidate definition；
- all eight workloads。

这适合一篇完整研究报告，不适合自动化 marathon。

一旦进入这个 DoD，系统会倾向于“把表填满”，而不是“及时判断这个方向不好”。

### 6.3 Prompt 没有区分 "hotspot discovery" 和 "optimization boundary"

`GENERIC_UACCESS = 63.2%` 是 hotspot discovery。

但 optimization boundary 需要额外条件：

- safe authority；
- stable recoverability；
- bounded state；
- consistent direction；
- owner/range attribution；
- limited special cases。

原 prompt 虽然强调了 MEPC 不是 authority，但执行目标仍然容易被 `GENERIC_UACCESS` 的大比例牵引。

更好的 prompt 应该明确：

> Hotspot share only authorizes investigation. It does not authorize broad validation or prototype unless candidate-quality metrics pass early thresholds.

### 6.4 Prompt 没有设置 negative-success 形态

这次最好的结果其实是一个负向结论：

> 这个 broad target 不适合作为当前主性能优化路线。

但原任务更多写的是：

- implement prototype；
- fix instrumentation；
- abandon target。

其中 “abandon target” 有写，但没有给出足够清晰的触发阈值和输出形态。

导致执行时会不断问：

- 是不是 instrumentation 还不够？
- 是不是再跑一个 workload？
- 是不是再修一个 marker？

未来应该把 negative-success 写得更明确：

> 如果第二个非平凡 workload 显示 recoverable coverage 低于阈值，或者 safety authority 缺失超过阈值，则停止并输出 negative feasibility report。不要继续 broad validation。

### 6.5 Prompt 没有限制 runtime-shaping attempts

为了复现 active-context non-loop / clear_page class，我们尝试了多种 shape：

- exact retry；
- amplification；
- large env；
- empty env；
- diagnostic probe。

这些都不是荒唐尝试，但累计起来变成了长尾探索。

未来 prompt 应该规定：

- 每个 coverage hypothesis 最多 1-2 个 runtime attempts；
- 如果不复现，转 source/static reasoning；
- 不允许为了一个 class 无限调 workload shape；
- coverage-incomplete 可以作为结论，不需要补到完美。

### 6.6 Prompt 没有把性能收益预算放在前面

最终我们关心的是性能优化。

但 prompt 更关注可行性细节，而没有提前规定：

- 预期收益阈值；
- validation 成本预算；
- 如果 narrow candidate 只覆盖 active subset，是否还值得做；
- 多少 workload / 多少小时后必须停下来。

未来这类任务应该先写：

> 我们最多投入 N 个验证 slice。如果 broad recoverability 不能稳定超过 X%，则不再追安全细节，直接换性能目标。

## 7. 这次实验的正向价值

虽然结论偏负面，但这次并不是浪费。

我们得到了几类重要资产：

### 7.1 明确了 RISC-V uaccess loop 的真实结构

确认了：

- `__asm_copy_from_user` / `__asm_copy_to_user` 共享低层 body；
- `fallback_scalar_usercopy` 是关键 loop；
- 一些 top PCs 对应具体 byte/word store/load；
- `__clear_user` / `clear_page` 不应混入 raw usercopy loop 解释。

### 7.2 建立了更好的 reporting 体系

现在可以区分：

- active wrapper candidate；
- inactive denominator；
- active context but non-loop PC；
- in-loop but range/fixup unrecoverable；
- PFN-owner root/range/ambiguous missing；
- cid match yes/no/unknown。

这对后续任何 trap attribution 工作都有价值。

### 7.3 证明了 active-wrapper 子集确实可恢复

这不是全局好目标，但它证明了机制可行性：

- wrapper context 可以传递足够信息；
- trap-time register/range/PFN 组合能恢复一部分 copy state；
- fail-closed classification 可以工作。

如果以后需要做 narrow demo，这些结果可复用。

### 7.4 发现了重要的负向边界

最重要的是，我们知道了哪些东西不能假设：

- 不能假设 broad loop MEPC 都有 wrapper context；
- 不能假设 active context 内的 trap 一定是 usercopy loop；
- 不能假设 PFN owner attribution 总是可用；
- 不能假设 workload 2 的干净形态能推广到 workload 6；
- 不能把 code-0 runtime success 当成 mediation feasibility。

## 8. 对后续工作的建议

### 8.1 归档当前 marathon

建议把这个 marathon 作为 T5.1 feasibility negative closeout 归档。

建议归档结论：

> Broad uaccess-loop mediation is not currently recommended as the main
> performance optimization target. The active-wrapper exact-owner subset may
> support a narrow mechanism demo, but the broad MEPC-family denominator is too
> fragmented for a clean, high-payoff, fail-closed portal.

### 8.2 开一个新的性能目标选择 packet

下一步不应该继续沿着 uaccess-loop 自动跑。

更好的新任务是：

> 从当前 PRIVATE_DATA trap families 中重新选择性能优化目标，比较语义边界清晰度、可恢复/可授权程度、预期收益、验证成本。

候选可以包括：

- mapping/update 类；
- rseq / robust futex ABI maintenance；
- teardown / exit path；
- syscall-buffer active-wrapper exact subset；
- 其他当前 top trap family。

这个新 packet 应该先做 target selection，不要一上来写 prototype。

### 8.3 如果继续 uaccess，只做窄 demo

如果出于论文或系统展示需要，仍然想保留 uaccess 方向，可以开一个很小的 demo packet：

- 只处理 active-wrapper rows；
- 只处理 direction known；
- 只处理 range in-bounds；
- 只处理 owner exact；
- 只处理 cid match yes；
- 只处理 bounded length；
- 所有其他状态 fail-closed；
- 明确不宣称 broad performance payoff。

这个 demo 的价值是展示机制，不是主要优化收益。

## 9. 给未来 Prompt 的模板建议

未来类似任务建议这样写：

```text
Goal:
  Decide whether target X is worth becoming a performance optimization project.

Budget:
  At most 2 instrumentation slices and 2 runtime validation slices before a
  human checkpoint.

Early stop:
  Stop and write negative closeout if:
  - recoverable coverage < 60% on any nontrivial workload, or
  - owner/range/cid authority is missing for >10% of candidate rows, or
  - reproducing one class requires more than 2 workload-shaping attempts, or
  - the target requires many semantic exclusions.

Positive route:
  Only after early metrics pass, create a prototype packet.

Negative route:
  A negative closeout is a valid success. Do not continue broad validation just
  to fill a table.
```

这能避免 marathon 被复杂边界吸走。

## 10. 最终一句话

这次长期马拉松的真实收敛结果是：

**我们证明了 uaccess-loop 是热点，也证明了它在真实 workload 下不是一个足够干净的 broad mediation 边界。**

这不是工程失败，而是一个应该尽早接受的负向 feasibility 结论。它帮我们避免继续把性能优化资源投入到一个会不断膨胀成语义测绘的目标上。
