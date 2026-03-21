# Current State

最后更新：2026-03-22

## 当前目标

在简单 fork smoke 已初步通过后，推进容器语义覆盖验证，重点看：
- 多 child / `wait` / pipeline
- shared memory / `mmap` / `MAP_SHARED`
- 小而真实的多进程应用
- 定向循环与并发压力下是否仍出现计数或页状态损坏

## 当前分支 / 检查点

- 主仓：`main`
- `linux/`：`main`
- `opensbi/`：`NoPIC`
- 稳定入口文档：`docs/agent/SESSION_BOOTSTRAP.md`

## 最新已知状态

- `VM_NACC` / agent aperture 误继承不是当前首要矛盾，相关 filter 路径已明显收敛。
- 先前的 child `ptp_list` 注册和 `ptdesc->ptl` 初始化问题已不再是主线首因。
- 用户于 2026-03-22 报告：简单 fork smoke
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"`
  已经“看起来可以通过”。
- 因此当前阶段目标应从“只盯 fork 会不会过”切到“容器语义是否足够完整”，尤其是：
  - 多进程共享内存
  - `mmap` / `MAP_SHARED`
  - 小而真实的动态链接应用
  - 定向压力下的稳定性
- 当前已接受的长期方向是 Linux-friendly fork：Linux 尽量回到原生 fork 主线，只在 secure 页表写入点依赖 OpenSBI，而不是继续把当前原型里的局部旁路实现或 `semantic replay` 当最终模型。
- `bitmap` 防护仍未实现，但目前被放在后续 security hardening 阶段，而非当前容器语义验证之前。
- `docs/workflow/` 已建立，后续新会话应以这里为当前状态入口，再回读 `docs/agent/` 的稳定知识。
- 主仓工作树当前不是干净状态；但 `linux/` 与 `opensbi/` 当前 `git status --short` 可视为干净，后续实验仍应显式记录 checkpoint。

## 阻塞项

- 2026-03-22 这次 smoke 通过还没有补入统一状态面：缺准确 checkpoint、日志路径和结果摘要。
- 还没有系统执行 Tier 0 到 Tier 2 测试，因此不能宣称 fork / `mmap` / shared memory 语义已稳定。
- 尚未确认先前 accounting 风险是否已经真正消失，还是只是没有在当前 smoke 场景中复现。
- `bitmap` 防护仍未进入实现阶段。

## 最新证据

- 用户口头报告（2026-03-22）：
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"`
  - 当前“看起来可以通过”
  - 但准确日志路径与 checkpoint 仍待补录
- `logs/fork_exec_default_freshwait_20260317_qemu_20260317_151037.log`
  - 这是上一轮已知最强负面证据：当时首个明确异常点仍是 `Bad rss-counter state` 与 `non-zero pgtables_bytes on freeing mm: -32768`
  - 后续若新测试不再复现，应明确把该日志降级为历史问题，而不是当前状态
- `docs/workflow/PLAN_20260322_container_validation.md`
  - 当前测试推进顺序已固定为 `coverage-first -> real-app -> targeted-stress`

## 本次更新后应优先补充

- 2026-03-22 smoke 通过对应的准确日志路径。
- 最新实验对应的源码 checkpoint 或 commit id。
- Tier 0 到 Tier 2 的执行结果，特别是 shared memory / `mmap` 相关命令。
