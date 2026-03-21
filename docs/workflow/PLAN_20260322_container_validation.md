# Container Validation Plan

## Goal

- 在 fork smoke 初步可通过之后，建立一套分层验证路线，用来判断 NaCC 是否已经具备容器场景需要的基础 Linux 语义。
- 特别强调：**容器背景下的多进程共享内存与 `mmap` 不是可选项，而是论文出发点之一。**

## Why Shared Memory / `mmap` Matters

- 容器里的多进程服务常依赖共享内存、文件映射和 `MAP_SHARED` 建立进程间数据通道。
- 动态链接、共享库、文件页缓存、匿名映射、`/dev/shm`、Python/Node/数据库类运行时，都会大量触发 `mmap` 相关语义。
- 因此，若 NaCC 想宣称自己支持“真实容器 workload”，就不能只证明 `fork + exec` 能走通；还要证明：
  - 多进程可以共享映射
  - child/peer 进程可以看到共享写入
  - teardown 后不会破坏计数与页状态

## Strategy

- 不直接在“真实应用”和“压力测试”之间二选一。
- 采用 **coverage-first -> real-app -> targeted-stress** 的顺序。
- 每一层都用尽量短的命令覆盖一种明确语义，避免一上来就用大应用把信号混杂。

## Tier 0: Baseline Regression

目标：
- 固化当前最小可通过 fork smoke

建议命令：

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"
```

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "echo alpha | wc -c; echo done"
```

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "for i in 1 2 3 4 5; do /bin/true; done; echo done"
```

通过标准：
- 命令返回 0
- 无明显 kernel BUG / panic / `Bad rss-counter state` / `Bad page state`

## Tier 1: Process Semantics

目标：
- 验证多 child、`wait`、pipeline、短命并发进程等基本容器用户态语义

建议命令：

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "for i in 1 2 3 4 5 6 7 8; do (echo child-$i)& done; wait; echo done"
```

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "sh -c 'echo inner-1'; sh -c 'echo inner-2'; echo done"
```

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "echo one | cat | wc -l; echo done"
```

通过标准：
- 无 child 卡死、`wait` 异常、异常退出码
- 无 teardown 后计数损坏

## Tier 2: Shared Memory / `mmap`

目标：
- 验证多进程共享内存与 `mmap` 语义
- 这是当前阶段的重点，不应晚于“真实应用”测试

### 2A. 匿名共享映射 + `fork`

```bash
docker run --security-opt seccomp=unconfined --rm python:3.11-slim python - <<'PY'
import mmap, os
buf = mmap.mmap(-1, 4096, flags=mmap.MAP_SHARED)
buf[:5] = b'hello'
pid = os.fork()
if pid == 0:
    buf[5:11] = b'child!'
    os._exit(0)
os.waitpid(pid, 0)
print(buf[:11].decode())
PY
```

预期：
- 输出 `hellochild!`

### 2B. 文件映射 + child 写回

```bash
docker run --security-opt seccomp=unconfined --rm python:3.11-slim python - <<'PY'
import mmap, os, tempfile
fd, path = tempfile.mkstemp()
os.write(fd, b'0' * 4096)
os.lseek(fd, 0, 0)
buf = mmap.mmap(fd, 4096, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
pid = os.fork()
if pid == 0:
    buf[:4] = b'data'
    buf.flush()
    os._exit(0)
os.waitpid(pid, 0)
os.lseek(fd, 0, 0)
print(os.read(fd, 4).decode())
os.close(fd)
os.unlink(path)
PY
```

预期：
- 输出 `data`

### 2C. `multiprocessing.shared_memory`

```bash
docker run --security-opt seccomp=unconfined --rm python:3.11-slim python - <<'PY'
from multiprocessing import Process
from multiprocessing.shared_memory import SharedMemory

def child(name):
    shm = SharedMemory(name=name)
    shm.buf[:4] = b'ping'
    shm.close()

shm = SharedMemory(create=True, size=4096)
p = Process(target=child, args=(shm.name,))
p.start()
p.join()
print(bytes(shm.buf[:4]).decode())
shm.close()
shm.unlink()
PY
```

预期：
- 输出 `ping`

通过标准：
- parent/child 之间共享写入可见
- 无异常 page fault / BUG / 计数损坏

## Tier 3: Small Real Applications

目标：
- 在基本语义通过后，跑一批“小而真实”的用户态
- 不直接上完整 Ubuntu 镜像

建议命令：

```bash
docker run --security-opt seccomp=unconfined --rm python:3.11-slim python -c "import subprocess; print(subprocess.check_output(['sh','-c','echo hi']).decode().strip())"
```

```bash
docker run --security-opt seccomp=unconfined --rm bash:5.2 sh -c "for i in 1 2 3; do echo loop-$i; done"
```

```bash
docker run --security-opt seccomp=unconfined --rm nginx:alpine nginx -t
```

选择原则：
- 动态链接
- 多进程或会 spawn child
- 会用到文件 IO / 配置解析 / 共享库 / `mmap`

## Tier 4: Targeted Stress

目标：
- 不做盲目压力，而是围绕已经通过的关键语义做重复与并发

建议命令：

### 4A. 当前 fork smoke 循环 100 次

```bash
for i in $(seq 1 100); do
  docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done" || break
done
```

### 4B. 并发 8 路短命容器

```bash
seq 1 8 | xargs -I{} -P8 docker run --security-opt seccomp=unconfined --rm busybox sh -c "echo parallel-{}; cat /etc/hostname >/dev/null; echo done"
```

### 4C. 共享内存测试循环

```bash
for i in $(seq 1 50); do
  docker run --security-opt seccomp=unconfined --rm python:3.11-slim python - <<'PY' || break
import mmap, os
buf = mmap.mmap(-1, 4096, flags=mmap.MAP_SHARED)
buf[:5] = b'hello'
pid = os.fork()
if pid == 0:
    buf[5:11] = b'child!'
    os._exit(0)
os.waitpid(pid, 0)
assert buf[:11] == b'hellochild!'
PY
done
```

观察重点：
- 稳定性
- teardown / reclaim
- `rss`
- `pgtables_bytes`
- 是否出现 `Bad page map / state`

## Tier 5: Later Milestones

- 完整 Ubuntu 级 workload
- 更重的多进程服务
- 长时间运行稳定性
- 安全 hardening

### Bitmap Protection

- `bitmap` 防护应纳入长期计划，但不放在当前 fork/mmap 语义收敛之前。
- 推荐顺序：
  1. 先把 fork + `mmap` + shared memory 基础语义做稳
  2. 再做 `bitmap` 防护，作为后续 hardening 项

## Exit Criteria For “Ready To Try Ubuntu”

- Tier 0 到 Tier 2 稳定通过
- 至少 2 到 3 个 Tier 3 小应用稳定通过
- Tier 4 的循环与并发测试不再稳定触发计数/页状态损坏
- 之后再把 Ubuntu 作为“更高层验收 workload”，而不是当前最先跑的目标
