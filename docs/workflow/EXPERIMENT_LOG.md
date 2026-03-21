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

## 2026-03-22 simple fork smoke（待补日志路径）

- Date/Time: 2026-03-22，准确时间待补
- Goal: 确认最小 fork smoke 是否已能正常通过
- Command Run: `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"`
- Expected Result: 输出主机名与 `done`，容器正常退出，不出现明显 kernel BUG
- Actual Result: 用户口头报告“看起来可以通过”
- Artifact/Log Path: 待补
- Conclusion: 这条命令可作为当前 Tier 0 基线，但必须尽快补 checkpoint 与日志路径，并继续推进 Tier 1 / Tier 2
