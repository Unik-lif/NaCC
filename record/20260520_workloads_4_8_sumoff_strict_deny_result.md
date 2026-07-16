# 2026-05-20 workloads 4-8 SUM-off strict-deny result

## 结论

这轮结果是一个正向信号：在当前 OpenSBI strict-deny 行为下，workloads 4、5、6、7、8 顺序执行完成，没有出现预期要捕获的第一个 kernel Oops / BUG 触发点。

更关键的是，五个 workload 的最终 PRIVATE_DATA 统计里仍然有 private-data trap 活动，但 SUM-bit-off 相关计数全部为 0。这说明之前 workload3 方向的修复/收敛，很可能已经覆盖了 workloads 4-8 在这轮实验中实际走到的相关路径。

边界：这不是“所有未来 workload 都不会触发 SUM-off 问题”的证明，也不是完整 strict-deny 设计正确性的证明。它只证明当前这组 bounded T2 workloads 4-8 没有再打到 SUM-off private-data trap，也没有暴露 kernel Oops / BUG。

## 运行范围

- Task packet: `docs/workflow/tasks/completed/TASK_20260520_113130_all_workloads_sum_off_walkthrough.md`
- 目标：在当前 OpenSBI strict-deny 模式下，从 workload 4 开始顺序运行到 workload 8，遇到第一个明确 kernel Oops / BUG 即停止并保存证据。
- 实际结果：workloads 4-8 全部完成，未发现明确 Oops / BUG。
- 构建动作：测试前发现 `qemu/target/riscv/cpu_bits.h` 有修改，test_runner 执行了 `make qemu`；`linux`、`opensbi`、`agent` 工作树当时为 clean。

## Workload 结果

| Workload | 用户态可见结果 | SSH auto exit | Oops / BUG marker | private traps total | sum_on | sum_off | sumoff_total |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: |
| 4 | hostname + `done` | 0 | none found | 3148 | 3148 | 0 | 0 |
| 5 | `alpha` + `done` | 0 | none found | 3754 | 3754 | 0 | 0 |
| 6 | `13 /etc/hostname` + `done` | 0 | none found | 3399 | 3399 | 0 | 0 |
| 7 | `6` + `done` | 0 | none found | 3839 | 3839 | 0 | 0 |
| 8 | `ping` | 0 | none found | 614 | 614 | 0 | 0 |

每个 workload 的最终 sumoff profile 都是：

```text
sumoff_total=0 sumoff_load=0 sumoff_store=0
class=user_like_low total=0 load=0 store=0
class=kernel_high total=0 load=0 store=0
```

也就是说：不是 private-data trap 消失了，而是这些 trap 全部落在 SUM-on 统计里，没有 SUM-off private-data trap。

## 保存日志

- Workload 4 QEMU: `logs/task_20260520_w04_01_20260520_114645_qemu_20260520_115155.log`
- Workload 4 VM: `logs/task_20260520_w04_01_20260520_114645_vm_20260520_115155.log`
- Workload 5 QEMU: `logs/task_20260520_w05_01_20260520_115215_qemu_20260520_115607.log`
- Workload 5 VM: `logs/task_20260520_w05_01_20260520_115215_vm_20260520_115607.log`
- Workload 6 QEMU: `logs/task_20260520_w06_01_20260520_115621_qemu_20260520_120011.log`
- Workload 6 VM: `logs/task_20260520_w06_01_20260520_115621_vm_20260520_120011.log`
- Workload 7 QEMU: `logs/task_20260520_w07_01_20260520_120037_qemu_20260520_120421.log`
- Workload 7 VM: `logs/task_20260520_w07_01_20260520_120037_vm_20260520_120421.log`
- Workload 8 QEMU: `logs/task_20260520_w08_01_20260520_120437_qemu_20260520_120813.log`
- Workload 8 VM: `logs/task_20260520_w08_01_20260520_120437_vm_20260520_120813.log`

## 解释

这轮实验原本想找的是 workload3 SUM-bit-off 问题收窄之后，后续 workload 是否会在 strict-deny 下暴露新的 kernel Oops / BUG。结果没有暴露新的失败点，而且 SUM-off 计数全为 0。

当前最合理的解释是：workload3 相关修复/收敛已经覆盖了 workloads 4-8 这轮会走到的 SUM-off 风险路径，或者这些 workload 当前没有再走到 SUM-off private-data 访问路径。两者都支持“没有继续扩散”的判断，但后者提醒我们不能把这轮结果外推成完整覆盖证明。

后续如果要继续推进，建议另开 bounded packet，目标不要混在这个已关闭实验里。可选方向包括：

- 扩大 workload 覆盖范围；
- 专门构造能命中 SUM-off kernel-high private-data load 的触发器；
- 加强 assertion，检查“应该为 0 的 SUM-off 计数必须为 0”；
- 回看 workload3 修复路径，确认为什么 workloads 4-8 的 SUM-off trap 现在归零。
