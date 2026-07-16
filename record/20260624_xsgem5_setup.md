# XS-GEM5 setup note

Date: 2026-06-24

Local checkout:
- `GEM5` branch: `xs-dev`
- commit: `648e24682a configs: should not define another numDelay in MicroTAGE (#916)[skip ci]`

What failed first:
- Building with the ambient shell picked up Anaconda tools:
  - `protoc`: `/home/link/anaconda3/bin/protoc`
  - `protoc --version`: `libprotoc 29.3`
  - `python3`: `/home/link/anaconda3/bin/python3`
  - `python3 --version`: `Python 3.13.5`
- System protobuf headers are Ubuntu protobuf `3.12.4`.
- Anaconda `protoc` generated `build/RISCV/proto/*.pb.h` with `Protobuf C++ Version: 5.29.3`, including `google/protobuf/runtime_version.h`, which is absent from the system protobuf 3.12 headers.

Fix applied:
- Cleaned only stale generated protobuf outputs with system toolchain in `PATH`:
  - `scons -c build/RISCV/proto/inst.pb.cc build/RISCV/proto/inst_dep_record.pb.cc build/RISCV/proto/packet.pb.cc`
- Rebuilt with system tools first in `PATH`:
  - `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`
  - `/usr/bin/protoc --version`: `libprotoc 3.12.4`
  - `/usr/bin/python3 --version`: `Python 3.10.12`
- Do not append the original Anaconda-heavy `PATH` during SCons runs.  It can expose Anaconda `grpc_cpp_plugin`; SCons then tries to link `-lgrpc++`, while system `libgrpc++` is not installed.

Successful build:
- Command log: `logs/gem5_setup/xsgem5_build_riscv_gem5_opt_system_path_after_proto_clean_20260624.log`
- Output binary: `GEM5/build/RISCV/gem5.opt`
- Binary size observed: about `1.1G`

Verification:
- `scripts/xsgem5-build.sh` completed successfully with strict system `PATH`.
- `GEM5/build/RISCV/gem5.opt -h` completed successfully.
- `GEM5/build/RISCV/gem5.opt GEM5/configs/example/kmhv3.py --help` completed successfully and showed the XiangShan full-system/checkpoint options.
- `GEM5/build/RISCV/gem5.opt --build-info` is not healthy in this fork/build: it prints `AttributeError: module 'm5.defines' has no attribute 'gem5Version'`.

Warnings left:
- HDF5 support is disabled because HDF5 development headers/libraries were not found.
- Backtrace support was not enabled because the configure probe failed under `-Werror`.
- These warnings did not block `gem5.opt` from building.

Helpers added:
- `scripts/xsgem5-env.sh`: source this before manual XS-GEM5 build/run commands.
- `scripts/xsgem5-build.sh`: bounded wrapper for `scons build/RISCV/gem5.opt --gold-linker -j8`.

## Build usage

Preferred repo-level build command:

```sh
make gem5
```

This calls `scripts/xsgem5-build.sh`, which:
- sources `scripts/xsgem5-env.sh`;
- uses strict system `PATH` so Anaconda `python3`, `protoc`, and `grpc_cpp_plugin` are not visible;
- builds `GEM5/build/RISCV/gem5.opt` with `scons build/RISCV/gem5.opt --gold-linker -j8`;
- applies a default `timeout` of 3600 seconds.

Useful overrides:

```sh
XSGEM5_JOBS=16 make gem5
XSGEM5_BUILD_TIMEOUT=7200 make gem5
```

Manual equivalent:

```sh
source scripts/xsgem5-env.sh
cd "$GEM5_HOME"
timeout 3600 scons build/RISCV/gem5.opt --gold-linker -j8
```

Do not build from the ambient shell if Anaconda is active.  Check the effective tools with:

```sh
source scripts/xsgem5-env.sh
which python3
python3 --version
which protoc
protoc --version
which grpc_cpp_plugin || true
```

Expected:
- `python3`: `/usr/bin/python3`
- `protoc`: `/usr/bin/protoc`
- `grpc_cpp_plugin`: not found unless system gRPC development libraries are also installed.

## Launch and smoke usage

Always source the XS-GEM5 environment before manual launches:

```sh
source scripts/xsgem5-env.sh
```

Basic binary smoke check:

```sh
"$GEM5_HOME/build/RISCV/gem5.opt" -h
```

Configuration smoke check:

```sh
"$GEM5_HOME/build/RISCV/gem5.opt" "$GEM5_HOME/configs/example/kmhv3.py" --help
```

Raw bare-metal binary example, matching the upstream README flow:

```sh
source scripts/xsgem5-env.sh
export GCBV_REF_SO=/absolute/path/to/riscv64-nemu-interpreter-c1469286ca32-so
"$GEM5_HOME/build/RISCV/gem5.opt" \
  "$GEM5_HOME/configs/example/kmhv3.py" \
  --raw-cpt \
  --generic-rv-cpt=/absolute/path/to/coremark-2-iteration.bin
```

Generic checkpoint example:

```sh
source scripts/xsgem5-env.sh
export GCBV_REF_SO=/absolute/path/to/riscv64-nemu-interpreter-so
export GCB_RESTORER=/absolute/path/to/gcpt.bin
"$GEM5_HOME/build/RISCV/gem5.opt" \
  "$GEM5_HOME/configs/example/kmhv3.py" \
  --generic-rv-cpt=/absolute/path/to/checkpoint.gz \
  --gcpt-restorer="$GCB_RESTORER"
```

XS-GEM5 currently expects full-system style inputs:
- raw bare-metal image with `--raw-cpt --generic-rv-cpt=<bin>`;
- or XiangShan/NEMU-style GCPT checkpoint with `--generic-rv-cpt=<checkpoint.gz>`.

The upstream scripts normally enforce Difftest.  For real runs, prepare the matching reference `.so` and restorer variables from the XS-GEM5/NEMU release/source flow:
- `GCBV_REF_SO`
- `GCB_REF_SO` if using a non-vector GCB reference path;
- `GCB_RESTORER`;
- `GCBV_RESTORER` if using RVV checkpoints;
- `GCB_MULTI_CORE_RESTORER` for supported multi-core GCB checkpoints.

For initial NaCC bring-up, the key open decision is whether to port the NaCC image into the XiangShan GCPT flow with Difftest enabled, or temporarily disable Difftest in `GEM5/configs/common/xiangshan.py` for early platform bring-up.  The latter is a local debugging choice; upstream docs say simulation errors without Difftest are not supported by maintainers.
