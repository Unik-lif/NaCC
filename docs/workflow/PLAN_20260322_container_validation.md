# Container Validation Plan

## Goal

- After partial fork-smoke progress, establish a layered validation route that answers whether NaCC already provides the baseline Linux semantics required for container workloads.
- Shared memory and `mmap` are not optional extras. They are part of the project motivation.

## Why Shared Memory / `mmap` Matters

- Multi-process container services often rely on shared memory, file mappings, and `MAP_SHARED`.
- Dynamic linking, shared libraries, file page cache, anonymous mappings, `/dev/shm`, and higher-level runtimes such as Python, Node, or databases all exercise `mmap` semantics heavily.
- Therefore, "fork + exec works" is not enough. NaCC must eventually show:
  - shared mappings visible across processes
  - parent/child or peer processes observing shared writes correctly
  - teardown without accounting or page-state corruption

## Strategy

- Do not force a binary choice between "real applications" and "stress testing".
- Use the order:
  - **coverage-first -> real-app -> targeted-stress**
- Each tier should use short commands that isolate one semantic at a time.

## Tier 0: Baseline Regression

Goal:

- freeze the current minimum smoke baseline

Suggested commands:

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"
```

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "echo alpha | wc -c; echo done"
```

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "for i in 1 2 3 4 5; do /bin/true; done; echo done"
```

Pass criteria:

- command returns 0
- no obvious kernel BUG / panic / `Bad rss-counter state` / `Bad page state`

## Tier 1: Process Semantics

Goal:

- validate multi-child behavior, `wait`, pipelines, and short-lived concurrent processes

Suggested commands:

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "for i in 1 2 3 4 5 6 7 8; do (echo child-$i)& done; wait; echo done"
```

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "sh -c 'echo inner-1'; sh -c 'echo inner-2'; echo done"
```

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "echo one | cat | wc -l; echo done"
```

Pass criteria:

- no hanging child
- no abnormal `wait`
- no suspicious exit code
- no post-teardown accounting corruption

## Tier 2: Shared Memory / `mmap`

Goal:

- validate multi-process shared-memory and `mmap` semantics
- this is the current priority tier and should not be postponed behind "real applications"

### 2A. Anonymous shared mapping plus `fork`

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

Expected output:

- `hellochild!`

### 2B. File-backed mapping plus child writeback

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

Expected output:

- `data`

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

Expected output:

- `ping`

Pass criteria:

- shared writes are visible across parent and child
- no abnormal page fault / BUG / accounting corruption

## Tier 3: Small Real Applications

Goal:

- run a small set of realistic user-space programs after basic semantics pass
- do not jump directly to full Ubuntu

Suggested commands:

```bash
docker run --security-opt seccomp=unconfined --rm python:3.11-slim python -c "import subprocess; print(subprocess.check_output(['sh','-c','echo hi']).decode().strip())"
```

```bash
docker run --security-opt seccomp=unconfined --rm bash:5.2 sh -c "for i in 1 2 3; do echo loop-$i; done"
```

```bash
docker run --security-opt seccomp=unconfined --rm nginx:alpine nginx -t
```

Selection rule:

- dynamic linking
- multi-process or child-spawning behavior
- file I/O / config parsing / shared libraries / `mmap`

## Tier 4: Targeted Stress

Goal:

- do not do blind stress
- stress only the semantics that have already passed at smaller scale

### 4A. Current fork smoke looped 100 times

```bash
for i in $(seq 1 100); do
  docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done" || break
done
```

### 4B. Eight-way short-lived container concurrency

```bash
seq 1 8 | xargs -I{} -P8 docker run --security-opt seccomp=unconfined --rm busybox sh -c "echo parallel-{}; cat /etc/hostname >/dev/null; echo done"
```

### 4C. Shared-memory loop

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

What to watch:

- stability
- teardown / reclaim
- `rss`
- `pgtables_bytes`
- `Bad page map / state`

## Tier 5: Later Milestones

- Ubuntu-class workloads
- heavier multi-process services
- long-duration stability
- security hardening

### Bitmap Protection

- `bitmap` protection belongs to the long-term plan, but should not be pulled ahead of fork / `mmap` / shared-memory semantic convergence.
- Recommended order:
  1. stabilize fork + `mmap` + shared-memory semantics
  2. add `bitmap` protection as a later hardening item

## Exit Criteria For "Ready To Try Ubuntu"

- Tier 0 to Tier 2 are stable
- at least 2 to 3 Tier 3 small applications pass stably
- Tier 4 loop and concurrency runs stop reliably reproducing accounting / page-state corruption
- only then should Ubuntu be treated as a higher-level validation workload instead of the immediate next step
