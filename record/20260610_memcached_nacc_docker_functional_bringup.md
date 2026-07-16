# Memcached NaCC Docker Functional Bring-Up

Date: 2026-06-10

Task: `TASK_20260609_155747_memcached`

## Outcome

Memcached was proven to run a minimal functional workload under NaCC Docker. This record is not a throughput benchmark closeout.

Observed successful probe:

- Fresh NaCC container runtime: `runc`
- NaCC options: `--security-opt seccomp=unconfined --ulimit core=0`
- Common image id: `sha256:5607c80eb619671f773c2502331434e1402c6dd11bfd9c57a3bb813d87b704e0`
- Direct memcached text-protocol check returned:
  - `STORED`
  - `VALUE nacc_probe 0 1`
  - `x`
  - `END`
- `memtier_benchmark` probe command returned `rc=0`.

Primary evidence root:

```text
logs/test_runner/TASK_20260609_155747_memcached/current_retry_20260610_103640_common_runtime_quiet_accept_help_rc/
```

Extracted guest bundle:

```text
logs/test_runner/TASK_20260609_155747_memcached/current_retry_20260610_103640_common_runtime_quiet_accept_help_rc/extracted_common_runtime/TASK_20260609_155747_memcached_common_runtime_20260610_023748/
```

## Reuse-First Rule

Future agents should not start by rebuilding benchmark images or creating Dockerfiles.

Use the existing guest Docker state first:

1. Check for the common benchmark image:

   ```sh
   docker images
   docker image inspect nacc-ae:benchmarks
   ```

2. Prefer the existing committed image:

   ```text
   nacc-ae:benchmarks
   sha256:5607c80eb619671f773c2502331434e1402c6dd11bfd9c57a3bb813d87b704e0
   ```

3. If the tag is missing but the saved image exists, reload or re-tag that exact artifact before rebuilding:

   ```text
   /root/tests/memcached/nacc-ae_benchmarks_TASK_20260609_155747_memcached_common_runtime_20260610_023748.tar
   sha256: f8a09000f4b3c2ccc9ac9c8d7f4bb4b978634fef023c70b395c0898b5b1dd9da
   ```

4. Preserve old containers as evidence. Do not delete `nacc_ae_native`, `nacc_ae_nacc`, or task-stamped containers unless the human explicitly approves cleanup.

5. If an existing task-stamped container is still valid, start it and `docker exec` into it instead of creating a replacement. Create fresh containers only when the runtime split must be re-established.

## Container Runtime Shape

Docker runtime is fixed at container creation. Do not try to change runtime with `docker start`.

Known good same-image split:

```text
native container:
  nacc_ae_native_TASK_20260609_155747_memcached_common_runtime_20260610_023748
  runtime: runc-origin
  image: sha256:5607c80eb619671f773c2502331434e1402c6dd11bfd9c57a3bb813d87b704e0

NaCC container:
  nacc_ae_nacc_TASK_20260609_155747_memcached_common_runtime_20260610_023748
  runtime: runc
  security_opt: seccomp=unconfined
  core_ulimit: 0:0
  image: sha256:5607c80eb619671f773c2502331434e1402c6dd11bfd9c57a3bb813d87b704e0
```

If fresh containers are needed from the same image:

```sh
docker create \
  --name nacc_ae_native_<run_id> \
  --runtime runc-origin \
  nacc-ae:benchmarks sleep infinity

docker create \
  --name nacc_ae_nacc_<run_id> \
  --runtime runc \
  --security-opt seccomp=unconfined \
  --ulimit core=0 \
  nacc-ae:benchmarks sleep infinity
```

Then start and enter with:

```sh
docker start <container>
docker exec -it <container> /bin/bash
```

Important Docker CLI note:

```sh
docker start <container> /bin/bash
```

does not enter a shell. Docker treats `/bin/bash` as a second container name and will report `No such container: bin/bash`.

## How The Image Was Produced

The accepted route was incremental reuse:

1. Use the existing AE base:

   ```text
   nacc-bench:jammy-nginx-lmbench-riscv64
   sha256:2e8da160f50d5b9d344a926ad2c525646c9fbdb1032aba1ee74b5972ad4fd282
   ```

2. Select the already prepared native-side filesystem baseline:

   ```text
   nacc_ae_native
   runtime: runc-origin
   image: sha256:2e8da160f50d5b9d344a926ad2c525646c9fbdb1032aba1ee74b5972ad4fd282
   ```

3. Repair/validate memcached, source-built `memtier_benchmark`, and runtime libraries in that container.

4. Commit that exact filesystem to:

   ```text
   nacc-ae:benchmarks
   sha256:5607c80eb619671f773c2502331434e1402c6dd11bfd9c57a3bb813d87b704e0
   ```

5. Create separate native and NaCC containers from that same image id.

This route keeps filesystem content constant and changes only Docker runtime/options.

## Minimal Functional Probe

The successful memtier probe command was:

```sh
memtier_benchmark \
  --server=127.0.0.1 \
  --port=11211 \
  --protocol=memcache_text \
  --data-size=1 \
  --clients=1 \
  --threads=1 \
  --requests=1 \
  --ratio=1:1
```

Recorded summary:

```text
mode    data_size_bytes    protocol         rc    elapsed_ms    throughput_kbsec
probe   1                  memcache_text    0     1268          1.75
```

The `1.75` KB/sec field is probe-only evidence. Do not use it as throughput data.

Probe artifacts:

```text
container-results-probe-nacc/events.log
container-results-probe-nacc/probe_memcached_response.normalized.txt
container-results-probe-nacc/probe_data_size_1.memtier.cmd.txt
container-results-probe-nacc/probe_data_size_1.memtier.stdout.log
container-results-probe-nacc/summary.tsv
```

## What Not To Claim

Do not claim formal memcached performance from this packet.

The formal matrix started after the passing probe, but the first native default memtier command used the default large workload and was manually terminated:

```text
mode: native
data_size_bytes: 16
rc: 143
elapsed_ms: 3331444
throughput_kbsec: empty
```

No completed native matrix, no NaCC formal matrix, no throughput summary, and no NaCC/native ratio exists.

The human later observed QEMU/Agent console messages such as:

```text
[Qemu] Agent will jump to twin_entry!
[Qemu] env->pc: ...
```

during ordinary Docker operations. Treat that as a quiet/no-log performance blocker for any future benchmark packet.

## Future Benchmark Route

If future work needs throughput:

1. First prove a clean/no-log VM/QEMU/runtime state.
2. Reuse `nacc-ae:benchmarks` and existing task-stamped containers when possible.
3. If runtime comparison requires fresh containers, create two containers from the exact same image id:
   - native: `--runtime runc-origin`
   - NaCC: `--runtime runc --security-opt seccomp=unconfined --ulimit core=0`
4. Use bounded memtier workload limits approved by planner/human, not memtier defaults.
5. Preserve all Docker image/container/runtime identity evidence before making performance claims.
