# Codex Prompt: Native Container vs Kata MicroVM Benchmarks

```text
请你在当前机器上为论文做一组 lightweight motivation benchmarks，只比较两类 container architecture：

1. Native container
   - Docker 默认的 runc runtime。
   - 代表普通 Linux container。

2. MicroVM-based container
   - Kata Containers。
   - 代表 container-in-microVM 架构。
   - 注意：普通 Kata 只能作为 microVM-based proxy，不能写成 confidential VM，除非本机确实配置了 TDX/SEV/CCA confidential mode。

目标：
生成一个可复现的小表格，用于论文 Introduction，说明 microVM-based container 即使运行极小 workload，也会引入可测的启动、内存、syscall/process 开销。不要做完整 evaluation。

环境约束：
- 当前是 Docker 环境。我们只需要安装并配置一个 Docker 可调用的 Kata runtime，使 `docker run --runtime=<kata-runtime> ...` 可以工作。
- 不需要 Kubernetes。
- 不需要搭建 containerd/nerdctl benchmark 路径。
- 如果 Docker 不可用，先报告问题并停止。

Kata Containers 安装/配置来源：
- 优先使用 Kata Containers 官方文档入口确认当前最新安装方式：
  https://katacontainers.io/docs/
- 官方文档的 Installation Guides 会跳到 Kata Containers GitHub：
  https://github.com/kata-containers/kata-containers/tree/main/docs/install
- Kata 官方 GitHub Releases 可用于查找最新 release 和官方 artifacts：
  https://github.com/kata-containers/kata-containers/releases
- 官方 install README 提醒 Kata Containers 需要 nested virtualization 或 bare metal。请先检查硬件/虚拟化能力，例如 `/dev/kvm` 是否存在、当前环境是否支持 nested virtualization。
- 先检查 Docker 是否已经配置 Kata runtime：
  `docker info`
  查看 `Runtimes` 中是否已有 `kata-runtime`、`kata`、`io.containerd.kata.v2`、`kata-qemu` 或类似名字。
- 如果 Docker 中已有 Kata runtime，直接使用已有 runtime，不要重新安装。
- 如果 Docker 中没有 Kata runtime，请按官方文档/官方 release 为当前发行版安装 Kata Containers，并配置 Docker daemon runtime。目标是在 Docker 的 `daemon.json` 或等价配置中注册 Kata runtime，例如让下面命令可用：
  `docker run --rm --runtime=<kata-runtime> alpine true`
- 如果需要修改 Docker daemon 配置，先备份原配置，修改后重启 Docker，并在 summary 中记录修改内容。
- 如果无法安装或当前环境不支持 KVM/nested virtualization，请只运行 native container，并把 Kata 标记为 unavailable，写清楚原因和官方安装链接。
- 不要使用来源不明的第三方安装脚本。不要伪造 Kata 数据。

需要测试四个指标：

A. Startup latency
定义：
从发起 container run 命令，到容器内最小 workload 执行结束的 end-to-end latency。

workload：
`alpine:latest true`

Native 示例：
`docker run --rm alpine true`
或显式：
`docker run --rm --runtime=runc alpine true`

Kata 示例：
根据实际 runtime 名称使用，例如：
`docker run --rm --runtime=kata-runtime alpine true`

测试要求：
- 先 `docker pull alpine:latest`，pull 时间不能计入。
- 每类 runtime warm up 5 次，不计入结果。
- 正式重复 50 次。
- 每次都创建 fresh container，并自动删除。
- 使用 Python `time.monotonic_ns()` 或 `/usr/bin/time -f "%e"` 记录 end-to-end 时间。
- 输出 median、mean、p95、min、max。
- 单位换算为 ms。

B. Idle memory footprint
定义：
启动一个 idle container 后，host 可用内存减少量，用来近似该 runtime 为一个空闲容器引入的 host-side memory footprint。

workload：
`alpine:latest sleep infinity`

Native 示例：
`docker run -d --name <name> alpine sleep infinity`

Kata 示例：
`docker run -d --name <name> --runtime=<kata-runtime> alpine sleep infinity`

测试方法：
- 使用 `/proc/meminfo` 中的 `MemAvailable`。
- 每次测试前确保脚本自己创建的同名容器已删除。
- 启动前等待 3 秒，读取 MemAvailable 作为 before。
- 启动 idle container。
- 等待 5 秒，让 runtime 稳定。
- 读取 MemAvailable 作为 after。
- footprint = before - after，单位 KiB，最终换算为 MB。
- 删除该 idle container。
- 等待 5 秒，让系统恢复。
- 重复 30 次。
- 输出 median、mean、p95、min、max。
- 说明该方法是 approximate host-side footprint，适合 Kata，因为 hypervisor、shim、guest kernel 可能不在容器 cgroup 内。

C. getpid latency
定义：
容器内执行大量 `getpid()` 系统调用的平均延迟，用来近似 syscall-heavy workload 的边界成本。

workload：
编译一个小 C 程序，在容器内循环调用 `getpid()`，用 `clock_gettime(CLOCK_MONOTONIC)` 计时。

程序逻辑：
- 默认迭代次数：1,000,000 次。
- warm-up：先调用 10,000 次 `getpid()`，不计入。
- 正式计时：循环调用 `getpid()` N 次。
- 输出 average ns/op。

C 程序：

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static uint64_t nsec_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

int main(int argc, char **argv) {
    long n = argc > 1 ? atol(argv[1]) : 1000000;
    volatile pid_t sink = 0;
    for (long i = 0; i < 10000; i++) sink = getpid();
    uint64_t start = nsec_now();
    for (long i = 0; i < n; i++) sink = getpid();
    uint64_t end = nsec_now();
    double avg = (double)(end - start) / (double)n;
    printf("avg_ns=%.2f total_ns=%llu sink=%d\n",
           avg, (unsigned long long)(end - start), (int)sink);
    return 0;
}
```

测试要求：
- 在 host 上编译 benchmark binary，然后 bind mount 到容器中运行，避免把编译时间计入。
- 每类 runtime warm up 5 次，不计入结果。
- 正式重复 30 次。
- 输出 median、mean、p95、min、max，单位 ns/op。
- 示例：
  `docker run --rm --runtime=<runtime> -v "$PWD/results/bin:/bench:ro" alpine /bench/getpid_bench 1000000`

D. fork latency
定义：
容器内反复执行 `fork()` + child `_exit(0)` + parent `waitpid()` 的平均延迟，用来近似 process creation / clone-heavy workload 的成本。

workload：
编译一个小 C 程序，在容器内循环执行 fork/wait。

程序逻辑：
- 默认迭代次数：1,000 次。
- warm-up：先 fork/wait 20 次，不计入。
- 正式计时：循环 fork/wait N 次。
- child 立即 `_exit(0)`。
- parent 用 `waitpid()` 等待。
- 输出 average us/op。

C 程序：

```c
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

static uint64_t nsec_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static int one_fork(void) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) _exit(0);
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? 0 : -1;
}

int main(int argc, char **argv) {
    long n = argc > 1 ? atol(argv[1]) : 1000;
    for (long i = 0; i < 20; i++) {
        if (one_fork() != 0) {
            perror("warmup fork");
            return 1;
        }
    }
    uint64_t start = nsec_now();
    for (long i = 0; i < n; i++) {
        if (one_fork() != 0) {
            perror("fork");
            return 1;
        }
    }
    uint64_t end = nsec_now();
    double avg_us = (double)(end - start) / (double)n / 1000.0;
    printf("avg_us=%.2f total_ns=%llu n=%ld\n",
           avg_us, (unsigned long long)(end - start), n);
    return 0;
}
```

测试要求：
- 在 host 上编译 benchmark binary，然后 bind mount 到容器中运行。
- 每类 runtime warm up 5 次，不计入结果。
- 正式重复 30 次。
- 输出 median、mean、p95、min、max，单位 us/op。
- 示例：
  `docker run --rm --runtime=<runtime> -v "$PWD/results/bin:/bench:ro" alpine /bench/fork_bench 1000`

请你实现一个脚本，例如：
`scripts/bench_native_vs_kata.py`

脚本需要自动完成：
1. 检查 Docker 是否可用。
2. 记录测试环境：
   - date
   - hostname
   - kernel version
   - CPU model
   - total memory
   - Docker version
   - available runtimes
3. Pull `alpine:latest`。
4. 探测 native runtime。
5. 探测 Kata runtime：
   - 从 `docker info` 中查找 kata。
   - 常见名字包括 `kata-runtime`、`kata`、`io.containerd.kata.v2`、`kata-qemu`、`kata-clh`。
   - 如果找不到，记录 Kata unavailable 和原因。
6. 编译 `getpid_bench` 和 `fork_bench` 到 `results/bin/`。
7. 运行 startup latency benchmark。
8. 运行 idle memory footprint benchmark。
9. 运行 getpid latency benchmark。
10. 运行 fork latency benchmark。
11. 保存原始 CSV：
    - `results/native_vs_kata_startup_raw.csv`
    - `results/native_vs_kata_memory_raw.csv`
    - `results/native_vs_kata_getpid_raw.csv`
    - `results/native_vs_kata_fork_raw.csv`
12. 生成汇总 Markdown：
    - `results/native_vs_kata_summary.md`

summary 里包含：
- Runtime availability table：
  - category: Native container / MicroVM-based container
  - runtime name
  - command used
  - available/unavailable
  - unavailable reason
- Startup latency table：
  - category, runtime, median ms, mean ms, p95 ms, min ms, max ms, n
- Idle memory footprint table：
  - category, runtime, median MB, mean MB, p95 MB, min MB, max MB, n
- getpid latency table：
  - category, runtime, median ns/op, mean ns/op, p95 ns/op, min ns/op, max ns/op, n
- fork latency table：
  - category, runtime, median us/op, mean us/op, p95 us/op, min us/op, max us/op, n
- Methodology notes：
  - startup latency is end-to-end `container run --rm alpine true`
  - idle memory footprint is approximated by host MemAvailable before/after `alpine sleep infinity`
  - getpid latency is measured inside the container by repeated `getpid()`
  - fork latency is measured inside the container by repeated `fork()` + `_exit(0)` + `waitpid()`
  - Kata, if tested without confidential mode, is reported only as MicroVM-based container, not Confidential VM

实现注意：
- 不要使用 destructive cleanup，比如 `docker system prune`。
- 只删除脚本自己创建的容器，容器名加唯一前缀，例如 `nacre-bench-*`。
- 如果 benchmark 中断，尽量 cleanup 自己创建的容器。
- 如果 Kata 不可用，继续完成 native 测试，并在 summary 中说明官方安装位置。
- 不要伪造 Kata 或 confidential VM 数据。
```
