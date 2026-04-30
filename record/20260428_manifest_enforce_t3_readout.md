## 2026-04-28

### Manifest Enforcement T3 Readout

Source of truth:

- task packet: [docs/workflow/tasks/active/TASK_20260425_204842_manifest_enforce.md](/home/link/NaCC/docs/workflow/tasks/active/TASK_20260425_204842_manifest_enforce.md)
- runner log: [logs/test_runner/TASK_20260425_204842_manifest_enforce_20260426_132359.log](/home/link/NaCC/logs/test_runner/TASK_20260425_204842_manifest_enforce_20260426_132359.log)
- QEMU/OpenSBI direct capture: [logs/TASK_20260425_204842_manifest_enforce_20260426_132359_qemu_direct_20260426_134046.log](/home/link/NaCC/logs/TASK_20260425_204842_manifest_enforce_20260426_132359_qemu_direct_20260426_134046.log)
- VM direct capture: [logs/TASK_20260425_204842_manifest_enforce_20260426_132359_vm_direct_20260426_134046.log](/home/link/NaCC/logs/TASK_20260425_204842_manifest_enforce_20260426_132359_vm_direct_20260426_134046.log)

### Short Conclusion

This T3 run is usable as the manifest-enforcement MVP proof.

It proves the important policy shape:

- the manifest reaches Linux and OpenSBI with nonzero layout records;
- OpenSBI audits known startup PT_LOAD segments;
- OpenSBI applies the manifest as a classifier, not as a permissive whitelist;
- `PRIVATE_INIT`, `MEASURED_RO`, and ordinary unknown leaves all become `PRIVATE_DATA`;
- the MVP shared-exception path remains empty;
- DSO records are generated and logged, but DSO runtime dispatch is explicitly deferred and therefore remains fail-closed rather than shared.

The run does not prove future DSO runtime-coordinate support, `dlopen`, JIT, or generic shared-memory policy. Those are later phases.

### Why This Was Judged Usable

The result was accepted because it passes four gates at the same time.

#### 1. Fresh Artifact Gate

The direct VM capture is tied to the intended run:

- line 1: `[NaCC][vm-run-start] 20260426_133100`
- line 9: exact non-seccomp command with `/tmp/nacc_manifest_echo.json`
- line 11: guest output `test`
- line 13: `[NaCC][ssh-auto-exit] code=0`

The direct QEMU capture is also fresh:

- line 4: `[NaCC][qemu-run-start] 20260426_133101`

This matters because several earlier attempts failed due to stale or misaligned pane capture. In this run, the direct VM and direct QEMU artifacts are the authoritative pair.

#### 2. Manifest Transport Gate

Linux registered the manifest with actual layout data:

- QEMU line 456: `layout_records=6`
- QEMU lines 457-462: records 0-5 are present:
  - records 0-1: `role=entry`
  - records 2-3: `role=interp`
  - records 4-5: `role=dso`

This fixes the earlier failed state where Linux logged `layout_records=0`.

#### 3. Audit And Coverage Gate

OpenSBI audited four startup records that have runtime coordinates:

- line 1760: `entry`, `MEASURED_RO`, `phdr_index=3`, `flags=5`
- line 1763: `entry`, `PRIVATE_INIT`, `phdr_index=4`, `flags=6`
- line 1766: `interp`, `MEASURED_RO`, `phdr_index=1`, `flags=5`
- line 1769: `interp`, `PRIVATE_INIT`, `phdr_index=2`, `flags=6`

The pre-entry coverage line is:

```text
total_user_leaf=3
agent_internal_leaf=0
manifest_covered_leaf=1
measured_ro_leaf=0
private_init_leaf=1
unknown_default_private_leaf=2
special_or_excluded_leaf=0
```

This is not the final whole-run summary. It is a pre-entry snapshot over currently present user leaves. Its value is that it proves the coverage walker is running before entry and already sees both manifest-covered and unknown ordinary leaves.

#### 4. Fail-Closed Enforcement Gate

The classifier logs show all required MVP classes choosing `PRIVATE_DATA`:

- `UNKNOWN_DEFAULT_PRIVATE action=PRIVATE_DATA`: lines 1780, 1782, and later lines such as 1941, 2024, 2091
- `PRIVATE_INIT action=PRIVATE_DATA`: line 1781, later lines 1921-1922 and 4660-4661
- `MEASURED_RO action=PRIVATE_DATA`: lines 1887-1902

The final region summaries are the compact proof that the run did not accidentally enable shared exceptions:

```text
startup_private_init=10
startup_measured_ro=36
startup_unknown_default_private=324
startup_shared_exception=0
leaf_private=370
shared=0
excluded=3
```

The important part is not that every startup page is covered by the manifest. The important part is that the uncovered ordinary pages are not treated as shared. They land in `startup_unknown_default_private` and are sealed as `PRIVATE_DATA`.

### Statistics To Keep Straight

#### Manifest Layout Records

| Role | Records | Runtime dispatch |
| --- | ---: | --- |
| entry | 2 | dispatched to OpenSBI |
| interp | 2 | dispatched to OpenSBI |
| dso | 2 | deferred, missing DSO runtime base |
| total | 6 | 4 dispatched, 2 deferred |

#### Pre-Entry Coverage Snapshot

| Counter | Value | Interpretation |
| --- | ---: | --- |
| `total_user_leaf` | 3 | present user leaves seen at the pre-entry walk |
| `manifest_covered_leaf` | 1 | one present leaf matched manifest coverage |
| `private_init_leaf` | 1 | one covered leaf was writable init data |
| `unknown_default_private_leaf` | 2 | two ordinary leaves were not manifest-covered and fail closed |
| `measured_ro_leaf` | 0 | no measured-ro leaf was present in this snapshot |
| `special_or_excluded_leaf` | 0 | no special/excluded leaf in this snapshot |

#### Final Region Summary

| Counter | Value | Approx. share of `leaf_private=370` |
| --- | ---: | ---: |
| `startup_private_init` | 10 | 2.7% |
| `startup_measured_ro` | 36 | 9.7% |
| `startup_unknown_default_private` | 324 | 87.6% |
| `startup_shared_exception` | 0 | 0% |

Interpretation:

- The workload is still dominated by unknown ordinary leaves.
- That is acceptable for this phase because the policy is fail-closed.
- A higher manifest coverage ratio can be a future quality improvement, but low coverage is not a safety failure as long as unknown ordinary leaves become `PRIVATE_DATA`.

### What DSO Means Here

DSO means dynamic shared object: a runtime shared library object, usually an ELF `.so` such as libc or another dependency loaded by the dynamic linker.

In this experiment, the manifest generator produced DSO records, and Linux logged them as `role=dso`. However, the current OpenSBI dispatch ABI only has stable runtime coordinates for:

- the main executable, called `entry` in the logs;
- the interpreter / dynamic loader, called `interp` in the logs.

For DSO records, Linux does not yet have an approved source of runtime base addresses to hand to OpenSBI. So it logs:

```text
reason=missing_dso_runtime_base
note=StepE DSO leaves remain fail-closed UNKNOWN_DEFAULT_PRIVATE
```

That is why DSO deferral is not a failure in this run.

The important distinction:

- bad behavior would be: "DSO not matched, so treat it as shared";
- current behavior is: "DSO not dispatchable yet, so it remains unknown and fail-closed private."

This matches the packet's MVP boundary. It intentionally avoids inventing Linux VMA path authority or solving `dlopen`/JIT/generic shared memory in this step.

### How To Read This Experiment Going Forward

The correct mental model is:

1. Manifest coverage is a precision improvement, not the safety baseline.
2. The safety baseline is fail-closed `UNKNOWN_DEFAULT_PRIVATE -> PRIVATE_DATA`.
3. Step E DSO records prove the generator and Linux payload can carry bounded DSO metadata, but they do not yet prove DSO runtime classification.
4. `startup_shared_exception=0` is a key safety signal for this MVP because shared exceptions are intentionally disabled.
5. The next meaningful expansion is not "make all DSO pages shared or trusted"; it is to add an approved DSO coordinate source, then rerun the same audit/coverage/classifier checks.

### Remaining Work

The next useful work item should be scoped separately:

- design how Linux or runc can provide trustworthy DSO runtime base coordinates;
- keep the fail-closed default unchanged while adding that coordinate source;
- rerun this same proof pattern and expect some `startup_unknown_default_private` counts to move into manifest-covered DSO classes;
- keep `startup_shared_exception=0` unless a separate shared-exception policy is deliberately introduced.

### 中文补充：这次实验现象应该怎么理解

这次实验的主线不是“Docker 跑通了”，而是“manifest-backed classifier 的安全语义跑通了”。

整个过程可以按下面的链条理解：

1. runc 在容器启动路径里读取 `/tmp/nacc_manifest_echo.json`。
2. Linux 收到 manifest，并记录 `layout_records=6`，说明这次不是空布局。
3. Linux 在 `nacc_invoke` 附近把有 runtime base 的 entry/interp 记录发给 OpenSBI。
4. OpenSBI 对 entry/interp 的 PT_LOAD 做 Step A audit。
5. OpenSBI 在进入用户态前做 Step B coverage 统计。
6. 后续页面被访问、需要做 PRIVATE_DATA 判定时，OpenSBI 走 Step C/D classifier。
7. 已知的 `PRIVATE_INIT` / `MEASURED_RO` 和未知普通页 `UNKNOWN_DEFAULT_PRIVATE` 都被封成 `PRIVATE_DATA`。
8. shared exception 没有打开，最终为 `startup_shared_exception=0`。

所以这次可以接受的根本原因是：manifest 没有被实现成“只有列在里面才保护”的白名单，而是作为已知 startup segment 的分类器；普通未覆盖页仍然 fail-closed。

### 中文补充：三个容易混淆的统计口径

这里有三类数字，不能混在一起看。

第一类是 manifest layout record 数量：

```text
layout_records=6
entry records=2
interp records=2
dso records=2
```

这个数字回答的是：“manifest 里带了多少 PT_LOAD 布局记录？”

第二类是最终 private leaf 数量：

```text
leaf_private=370
startup_private_init=10
startup_measured_ro=36
startup_unknown_default_private=324
startup_shared_exception=0
```

这个数字回答的是：“最终有多少 leaf 被判成 PRIVATE_DATA，以及它们来自哪些 startup classifier 类别？”

第三类是 PRIVATE_DATA trap 次数：

```text
PRIVATE_DATA trap stats: load=6283 store=1235 total=7518
```

这个数字回答的是：“这些 private page 后续被访问时，产生了多少次 mediated trap？”

最重要的区别：

- `leaf_private=370` 是页数量；
- `total=7518` 是访问触发 trap 的次数；
- 一个 private leaf 可以被访问很多次，所以 trap 次数可以远大于 private leaf 数量。

### 中文补充：private leaf 数量统计

最终 region summary 里，private leaf 的 startup classifier 分布是：

| 类别 | leaf 数量 | 占 `leaf_private=370` 的比例 | 解释 |
| --- | ---: | ---: | --- |
| `startup_private_init` | 10 | 2.7% | manifest 命中的可写初始化段 |
| `startup_measured_ro` | 36 | 9.7% | manifest 命中的只读测量段 |
| `startup_unknown_default_private` | 324 | 87.6% | manifest 没覆盖到的普通页，默认 private |
| `startup_shared_exception` | 0 | 0% | MVP 没有开启 shared exception |

这个分布说明当前 manifest 覆盖还不高，绝大多数 private leaf 还是 unknown fallback。但这不是安全失败，因为 fallback 策略是 `UNKNOWN_DEFAULT_PRIVATE -> PRIVATE_DATA`。

换句话说：

- 覆盖率低，说明 precision 还有提升空间；
- unknown 数量大，不代表 shared 漏洞；
- 只要 unknown 被封成 PRIVATE_DATA，安全基线就是保守的。

### 中文补充：PRIVATE_DATA trap 统计

这次运行的 PRIVATE_DATA trap 总数是：

| 类型 | 次数 | 比例 |
| --- | ---: | ---: |
| load | 6283 | 83.6% |
| store | 1235 | 16.4% |
| total | 7518 | 100% |

这说明这次 `busybox echo test` 的 PRIVATE_DATA trap 明显偏 load-heavy。

日志里还把 trap 分成两个 category：

| Category | load | store | total | 比例 |
| --- | ---: | ---: | ---: | ---: |
| `syscall_buffer_path` | 1670 | 1235 | 2905 | 38.6% |
| `teardown_mapping_update` | 4613 | 0 | 4613 | 61.4% |

这里的现象比较重要：

- `syscall_buffer_path` 代表正常 syscall buffer / usercopy 路径上的 private access。
- `teardown_mapping_update` 代表退出、清理、映射更新阶段触发的 private access。
- 这次最大头是 teardown / mapping update 的 load trap，不是 store，也不全是普通 syscall buffer。

这说明目前的 trap 开销不仅来自容器程序运行中的读写，还来自进程生命周期后段的映射拆除或状态同步。

### 中文补充：热点 provenance 统计

日志还打印了几个最热的 PRIVATE_DATA provenance。这个表不是全量分类，只是热点来源，用来判断 trap 热点大概落在哪些 VA range 和 region class。

| Provenance | Hits | Load | Store | Region class | Range | 解释 |
| --- | ---: | ---: | ---: | --- | --- | --- |
| 0 | 522 | 49 | 473 | `PRIVATE_STRICT_ANON` | `[3fd1da4000,3fd1dc5000)` | 匿名私有区，store-heavy |
| 1 | 459 | 79 | 380 | `PRIVATE_STRICT_ANON` | `[3f9b19c000,3f9b19e000)` | 匿名私有区，store-heavy |
| 2 | 157 | 6 | 151 | `PRIVATE_FILE_COW` | `[3f9b39b000,3f9b3be000)` | 文件/COW 区，store-heavy |
| 3 | 56 | 0 | 56 | `PRIVATE_FILE_COW` | `[2ab12e6000,2ab13df000)` | 文件/COW 区，store-only |
| 4 | 8 | 0 | 8 | `PRIVATE_STRICT_ANON` | `[3f9b2f8000,3f9b304000)` | 小匿名私有热点 |

按这几个热点合计：

```text
PRIVATE_STRICT_ANON hot hits = 522 + 459 + 8 = 989
PRIVATE_FILE_COW hot hits   = 157 + 56      = 213
```

所以热点表里，匿名私有区仍然比 file/COW 区更重。

但要注意一个边界：provenance 只列 top entries，不是完整全量分桶。它适合看热点，不适合直接当作全局 trap class 分布。

### 中文补充：当前还缺什么统计

现在日志已经回答了这些问题：

- 有多少 private leaf？
- private leaf 大体来自哪些 startup classifier 类别？
- 总共发生了多少 PRIVATE_DATA trap？
- trap 是 load 多还是 store 多？
- top provenance 热点在哪些 VA range？
- top provenance 属于 `PRIVATE_STRICT_ANON` 还是 `PRIVATE_FILE_COW`？

但现在还不能精确回答这个问题：

```text
PRIVATE_INIT 具体产生了多少 trap？
MEASURED_RO 具体产生了多少 trap？
UNKNOWN_DEFAULT_PRIVATE 具体产生了多少 trap？
```

原因是当前 trap stats 的 attribution 主要按 access category、provenance range、region class 记录；而最终 manifest classifier 计数按 startup class 记录。两者不是同一张表。

特别要注意：

- `manifest classifier leaf ... count=N` 不是 trap 总数；
- 它是 classifier 对某类 leaf 做判定/应用时的累计计数；
- 不能把它直接解释成“这个类触发了 N 次 trap”。

如果后续要精确回答“哪个 manifest class 最贵”，需要新增一组 trap 计数器。

建议的新增统计项：

```text
trap_private_init_load
trap_private_init_store
trap_measured_ro_load
trap_measured_ro_store
trap_unknown_default_private_load
trap_unknown_default_private_store
trap_special_or_excluded_load
trap_special_or_excluded_store
```

实现方式上，有两个选择：

1. 在 trap attribution 时重新用 VA 查 startup manifest classifier；
2. 在 leaf 被首次判定成 PRIVATE_DATA 时缓存 startup class，后续 trap 直接读缓存 class。

第二种运行时开销更低，但需要更明确的数据结构生命周期设计。

### 中文补充：可以拿去讨论的核心问题

如果你要拿这份结果去和 ChatGPT 或别人讨论，可以把问题压成下面几句：

```text
We implemented a manifest-backed startup page classifier in OpenSBI for a RISC-V confidential container prototype.

The manifest is not used as a permissive whitelist. It classifies known startup PT_LOAD segments. Ordinary user leaves not covered by the manifest fail closed to PRIVATE_DATA.

In the accepted T3 run, Linux delivered layout_records=6: 2 entry records, 2 interpreter records, and 2 DSO records. Entry/interpreter records were dispatched to OpenSBI and audited. DSO records were logged but deferred because the current ABI lacks DSO runtime base coordinates.

Final OpenSBI summary:
leaf_private=370
startup_private_init=10
startup_measured_ro=36
startup_unknown_default_private=324
startup_shared_exception=0

PRIVATE_DATA trap stats:
load=6283
store=1235
total=7518

Trap categories:
syscall_buffer_path total=2905
teardown_mapping_update total=4613

The question is how to interpret the high UNKNOWN_DEFAULT_PRIVATE count and how to design the next attribution counters to split trap cost by manifest class.
```

这个问题的正确讨论方向不是“unknown 很多是不是错了”，而是：

- unknown 很多说明 manifest 覆盖还有限；
- fail-closed 说明安全语义是保守的；
- 下一步要优化 coverage 和 attribution；
- DSO runtime coordinate 是后续扩展，不是当前 proof 的失败点。
