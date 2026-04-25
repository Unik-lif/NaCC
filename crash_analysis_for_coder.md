# 2026-03-23 alpha_cat_no_wrapper 日志分析

## Crash Symptom

- 对应日志：
  - `logs/alpha_cat_no_wrapper_20260323_001326_qemu_20260323_001624.log`
  - `logs/alpha_cat_no_wrapper_20260323_001326_vm_20260323_001624.log`
- VM 侧现象：
  - 只看到 auto-run 命令
  - 没有 `alpha`、没有 `done`
  - 也没有回到 shell prompt
- QEMU 侧首个异常簇：
  - `do_page_fault` -> `Kernel filemap_map_pages` -> `handle_page_fault ... SEGV_ACCERR`
  - 关键行：
    - `logs/alpha_cat_no_wrapper_20260323_001326_qemu_20260323_001624.log:912`
    - `logs/alpha_cat_no_wrapper_20260323_001326_qemu_20260323_001624.log:926`
    - `logs/alpha_cat_no_wrapper_20260323_001326_qemu_20260323_001624.log:939`
- 重要限制：
  - 截至该日志结束，**没有看到 `sys_pipe2` / `sys_clone` / `sys_wait4`**
  - 因此这份证据不足以支持“pipe 本身是首因”

## Root Cause

当前更像是：

- `busybox sh -c "echo alpha | cat; echo done"` 这条 workload 在真正进入 shell pipeline 之前，
  就已经在 file-backed 映射 / page fault 路径上反复打转。
- 日志里多次出现 `Kernel filemap_map_pages` 和 `SEGV_ACCERR`，说明异常点更靠近：
  - 用户态程序装载后的文件映射访问
  - 或 `cat`/`sh` 相关页被 demand fault 拉入时的权限/映射语义
- 因为还没看到 `sys_pipe2`，所以不能把问题收敛成“pipe 语义坏了”；更准确地说，是
  **`cat` 这个 workload 复现了更早的 `mmap/filemap/page-fault` 语义缺口**。

## Action Items

1. 先在 `do_page_fault` / `handle_page_fault` 相关观测点里区分：
   - 当前 fault 地址是否落在 `cat`/`sh` 的 text、rodata、file-backed private mapping
   - fault 后是否真的成功补齐了用户 PTE
2. 针对 `Kernel filemap_map_pages` 路径补最小观测：
   - fault address
   - VMA flags
   - file-backed / anonymous
   - 最终 PTE 权限位
3. 不要直接把修复目标写成 pipe。
   - 下一步更适合先验证：
     - `docker run ... busybox cat /etc/hostname`
     - `docker run ... busybox sh -c "echo alpha; echo done"`
     - `docker run ... busybox sh -c "echo alpha | cat; echo done"`
   - 用来切开 `cat` 本身、shell、本轮 pipeline 这三层
4. 如果 coder 要补断言，优先放在：
   - file-backed page fault 完成后用户 PTE 是否存在且权限正确
   - fault 重试前后是否还在同一 mm / 同一 VMA / 同一 NaCC 状态
