# Experiment Log

新实验追加到顶部。每条都要能指回日志或产物路径。

---

## Entry Template

- Date/Time:
- Goal:
- Command Run:
- Expected Result:
- Actual Result:
- Artifact/Log Path:
- Conclusion:

---

## 2026-04-09 minimal static POSIX shm repro in container

- Date/Time: 2026-04-09 10:47 to 10:56 CST
- Goal: reduce the noisy Python `multiprocessing.shared_memory` case to a minimal container-side POSIX shm repro and verify whether the recent `VM_NACC` / `total_vm` accounting fix removes the child-side `mmap -> -ENOMEM`
- Command Run: `docker run --security-opt seccomp=unconfined --rm -v /root/nacc_shm_repro:/nacc_shm_repro:ro busybox /nacc_shm_repro`
- Expected Result: container prints `ping`, child `shm_open + mmap(MAP_SHARED)` succeeds, and QEMU logs no longer show `may_expand_vm failed` on the child `mmap`
- Actual Result: passed; VM log printed `ping`, and QEMU log showed sane child `total_vm=190` with successful child `sys_mmap`
- Artifact/Log Path:
  - [batch_01_20260409_104749_vm_20260409_105641.log](/home/link/NaCC/logs/batch_01_20260409_104749_vm_20260409_105641.log)
  - [batch_01_20260409_104749_qemu_20260409_105641.log](/home/link/NaCC/logs/batch_01_20260409_104749_qemu_20260409_105641.log)
- Conclusion: the earlier child-side POSIX shm failure was immediately tied to `VM_NACC`-related `total_vm` underflow during `dup_mmap()`, and the current fix is sufficient to make this minimal Tier 2-style shared-memory case pass in the confidential-container path

---

## 2026-03-22 simple fork smoke（待补日志路径）

- Date/Time: 2026-03-22，准确时间待补
- Goal: 确认最小 fork smoke 是否已能正常通过
- Command Run: `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"`
- Expected Result: 输出主机名与 `done`，容器正常退出，不出现明显 kernel BUG
- Actual Result: 用户口头报告“看起来可以通过”
- Artifact/Log Path: 待补
- Conclusion: 这条命令可作为当前 Tier 0 基线，但必须尽快补 checkpoint 与日志路径，并继续推进 Tier 1 / Tier 2
