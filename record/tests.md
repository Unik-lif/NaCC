## 跑 benchmarks

下面是目前 `record/` 和 `docs/` 中已经沉淀下来的初步对比结果。这里的
“NaCC”多数情况下指当前 Docker `--runtime runc` 的 NaCC-patched 路径；
“native/origin”按各实验记录分别是 direct guest、default Docker、或
`runc-origin`。这些数值先作为阶段性对照，不当作最终论文级 benchmark。

### LTP

LTP 现在主要是可运行性/runner-shape 证据，不是 NaCC 性能 benchmark。

| 场景 | 条目数 | `rc=0` | 主要非零情况 | 备注 |
| --- | ---: | ---: | --- | --- |
| direct RISC-V guest | 1506 | 1181 | `rc=32`: 272, `rc=2`: 9, `rc=127`: 13, `rc=124`: 10, `rc=137`: 3 | 当前 direct guest baseline |
| default Docker | 1506 | 898 | `rc=32`: 203, `rc=2`: 269, `rc=127`: 45, `rc=124`: 9, `rc=137`: 3 | Docker policy/capability/seccomp 影响很大 |
| `dockero` / `runc-origin` | 1506 | 896 | `rc=2`: 269, `rc=32`: 204, `rc=127`: 45, `rc=124`: 11, `rc=137`: 3 | 和 default Docker 基本一致 |
| NaCC shell-mode probe | 2 | 1 | `seccomp01 rc=2` | `getpid01 rc=0`；`seccomp01` 符合 Docker/container policy 影响 |
| NaCC/default-policy sample50 | 50 | 26 | non-zero 24；LTP sub-results: passed 328, failed 20, broken 13, skipped 20, warnings 2 | 后来确认这更像 default-Docker runner sample，不是完整 NaCC 覆盖样本 |

关键结论：direct guest 比 Docker 多 `+285` 个 entry-level `rc=0`，Docker 里的
`rc=2` 大量来自容器策略/能力边界，不应直接算作 NaCC syscall 语义失败。

### lmbench

可引用的较干净对比是 same-daemon 三次 repeat：
`runc-origin` vs 当前 NaCC `--runtime runc`。`selected_metrics.tsv` 有 84 行，
其中 76 个 selected values 被解析出来。下面是 P0 项三次平均值。

| case | origin 平均 | NaCC 平均 | NaCC / origin | 方向 |
| --- | ---: | ---: | ---: | --- |
| `lat_syscall_null` | 4.968567 us | 4.894467 us | 0.985086 | latency，低更好 |
| `lat_syscall_read` | 8.522833 us | 8.388833 us | 0.984278 | latency，低更好 |
| `lat_syscall_write` | 5.892200 us | 5.924067 us | 1.005408 | latency，低更好 |
| `lat_pipe` | 730.357067 us | 705.012467 us | 0.965298 | latency，低更好 |
| `bw_pipe` | 47.803333 MB/s | 47.983333 MB/s | 1.003765 | bandwidth，高更好 |
| `bw_mem_1m_rd` | 11399.853333 MB/s | 14793.436667 MB/s | 1.297687 | bandwidth，高更好；波动较大 |
| `bw_mem_1m_wr` | 11509.960000 MB/s | 9389.956667 MB/s | 0.815811 | bandwidth，高更好；repeat 3 有明显 NaCC 低值 |

初步看 P0 syscall/pipe 项基本同量级，`null/read` 有小幅 NaCC-lower 信号，
`write` 基本持平。memory bandwidth 波动大，不适合强 claim。

### nginx

nginx 已完成 static-object matrix：8 个 object size，每个 3 次 repeat，
native 24 行 + NaCC 24 行，全部 `rc=0`，`failed_requests=0`，
每行目标传输 `1073741824` bytes，concurrency `16`。

`transfer_rate_kbytes_per_second` 三次平均：

| object size | native avg KB/s | NaCC avg KB/s | NaCC / native |
| ---: | ---: | ---: | ---: |
| 4096 | 1460.51 | 1461.60 | 1.000746 |
| 8192 | 2823.04 | 2790.34 | 0.988418 |
| 16384 | 5511.39 | 5363.55 | 0.973175 |
| 32768 | 10410.65 | 10082.00 | 0.968432 |
| 65536 | 14464.58 | 13741.30 | 0.949997 |
| 131072 | 23247.56 | 22373.31 | 0.962394 |
| 262144 | 32997.06 | 33143.05 | 1.004424 |
| 524288 | 44070.83 | 43504.52 | 0.987150 |

所有 24 行简单平均：native `16873.20` KB/s，NaCC `16557.46` KB/s，
NaCC/native `0.981287`，约低 `1.87%`。这是单次 matrix，不是统计结论。

### hackbench

当前 Hackbench 是诊断证据，不是 clean benchmark。matched-wrapper 采用：

```text
hackbench -T -g 25 -f 40 -s 100 -l 5
```

它会创建 `25 * (40 receiver + 40 sender) = 2000` 个 pthread worker。

| arm | runtime | rc | wrapper elapsed | Hackbench `Time:` | wrapper - internal |
| --- | --- | ---: | ---: | ---: | ---: |
| origin | `runc-origin` | 0 | 36586 ms | 16.188 s | 20399 ms |
| NaCC | `runc` | 0 | 168035 ms | 24.320 s | 143715 ms |

比例：

| metric | NaCC / origin |
| --- | ---: |
| Hackbench internal `Time:` | 1.5025 |
| wrapper elapsed | 4.593 |
| mode-to-time observed bucket | 7.687 |

解释边界：Hackbench 的 `Time:` 从 worker ready 后开始算，大量 NaCC gap 在
worker setup/readiness 之前；所以当前主要暴露初始化/创建 worker 开销。
更大的 `-l 100` NaCC 目标规模 run 还触发过 `CONTAINER_FULL` /
fork-child attach failure，不应当作为已通过性能结果引用。

### netperf

netperf 已完成 existing-container T3 validation，5 个 30s 子测试均 `rc=0`。

| test | native | NaCC | 单位 | NaCC / native |
| --- | ---: | ---: | --- | ---: |
| `TCP_STREAM` | 486.69 | 480.41 | 10^6 bits/sec | 0.987097 |
| `TCP_CRR` | 131072 | 131072 | netperf table 原单位 | 1 |
| `TCP_RR` | 131072 | 131072 | netperf table 原单位 | 1 |
| `UDP_STREAM` | 403.96 | 426.42 | 10^6 bits/sec | 1.0556 |
| `UDP_RR` | 212992 | 212992 | netperf table 原单位 | 1 |

初步看网络 microbenchmark 没有明显 NaCC 损失；但这是一组 single-run matrix。

### memcached

目前只有功能 proof，没有正式 throughput 结果。

| 项 | 数值/结果 |
| --- | --- |
| NaCC probe runtime | `runc` |
| probe rc | 0 |
| direct text protocol | `STORED` / `VALUE nacc_probe 0 1` / `x` / `END` |
| minimal memtier | `clients=1`, `threads=1`, `requests=1`, `data-size=1`, `ratio=1:1` |
| recorded throughput field | `1.75` KB/sec，明确只作为 probe evidence，不能作为性能数据 |
| formal matrix | 未完成 |
| first native formal memtier | `data_size_bytes=16`, `rc=143`, `elapsed_ms=3331444`, throughput empty |

结论：memcached 现在只能说 NaCC Docker 路径可运行到最小 set/get + one-request
probe；还没有 native/NaCC throughput ratio。

### SQLite

SQLite 已经跑通 lightweight smoke/performance sanity。两边均使用 existing
Docker arms：

| arm | container | runtime | SQLite |
| --- | --- | --- | --- |
| native | `nacc_ae_native` | `runc-origin` | 3.53.2 |
| NaCC | `nacc_ae_nacc` | `runc` | 3.53.2 |

共同证据：

| 项 | 数值 |
| --- | --- |
| sqlite path | `/test/sqlite/bin/sqlite3` |
| sqlite binary sha256 | `a2239f87fb0278e71b0e528e999780491593e5303d36cb89ce82494f13ebb034` |
| workload SQL sha256 | `90f096d2eed294fba813686e4683d1e9b30fc638d079a5e7a75afd15d821a743` |
| workload rc | native `0`, NaCC `0` |
| workload stdout sha256 | 两边同为 `359acb6708a3947edf601746d395175f8d5012322782f2679bc155221adb28de` |

rough timing 使用 guest `date +%s%N` 包住 `docker exec`：

| metric | value |
| --- | ---: |
| native real | 3.627455 s |
| NaCC real | 3.305148 s |
| NaCC / native | 0.911148 |

这是 single-run smoke sanity：能证明 SQLite 路径跑通，且没有极端性能差距；
不能证明 repeatability、steady-state performance 或最终 benchmark image readiness。
