# NaCC 虚拟磁盘坏盘修复记录（2026-03-16）

## 1. 现象

VM 内出现如下错误：

```text
EXT4-fs error (device vda1): ext4_ext_remove_space: ... bad header/extent: invalid magic
Aborting journal on device vda1-8.
EXT4-fs (vda1): Remounting filesystem read-only
Cannot execute /bin/sh: Input/output error
```

关键信号：

- `vda1` 的 ext4 元数据损坏
- journal 被中止
- 根文件系统被重新挂成只读
- 连 `/bin/sh` 都无法执行

这说明问题不在 shell 本身，而在 guest rootfs。

## 2. 首先判断坏的是哪一层

先检查 `qcow2` 容器是否损坏：

```bash
cd /home/link/NaCC
./riscv-qemu/bin/qemu-img info NaCC.qcow2
./riscv-qemu/bin/qemu-img check NaCC.qcow2
```

本次结果：

- `qemu-img check` 正常
- 因此 `qcow2` 外壳没坏
- 真正损坏的是镜像内部的 ext4 文件系统

## 3. 风险最大的成因

结合项目 Makefile，系统盘 `NaCC.qcow2` 会被两类路径同时使用：

1. QEMU 启动时作为来宾磁盘：
   - `make launch`
2. 宿主机更新 rootfs 时通过 `qemu-nbd` 直接读写：
   - `make disk`
   - `make rootfs`
   - `make rootfs-setup`
   - `make modules-update`
   - `make modules-update-wrapper`

因此最危险的情况是：

- VM 还在运行时，宿主机又把同一个 `NaCC.qcow2` 挂出来写

这会导致并发写盘，ext4 很容易损坏。  
另一种常见原因是 QEMU 被异常杀死，journal 没来得及正常落盘。

## 4. 本次修复思路

正常修法是：

```bash
sudo qemu-nbd -c /dev/nbd0 NaCC.qcow2
sudo e2fsck -f -y /dev/nbd0p1
```

但当前环境拿不到 `sudo` 密码，所以改用 `libguestfs/guestfish` 在用户态修。

核心思路：

- 不修 `qcow2` 外壳
- 直接对镜像里的 `/dev/sda1` 跑 `e2fsck`

## 5. 实际修复步骤

### 5.1 先备份

```bash
cd /home/link/NaCC
cp --reflink=auto -p NaCC.qcow2 NaCC.qcow2.pre_fsck.bak
```

### 5.2 由于宿主环境受限，需要给 `libguestfs` 指定可读内核与运行目录

原因：

- 默认宿主内核 `/boot/vmlinuz-6.8.0-90-generic` 权限是 `600`
- `libguestfs` 默认会用它构建 appliance，导致失败
- 需要改用一份世界可读的旧内核

本次可用配置：

```bash
export HOME=/tmp
export TMPDIR=/tmp
export XDG_RUNTIME_DIR=/tmp
export SUPERMIN_KERNEL=/boot/vmlinuz-6.7.0-rc6-next-20231222-snp-host-b865a087fcb7
export SUPERMIN_MODULES=/lib/modules/6.7.0-rc6-next-20231222-snp-host-b865a087fcb7
```

### 5.3 确认分区

```bash
virt-filesystems --long -h --all -a NaCC.qcow2
```

本次识别结果：

- `/dev/sda1` 是 ext4 rootfs

### 5.4 执行修复

```bash
guestfish --rw -a NaCC.qcow2 <<'EOF'
run
e2fsck /dev/sda1 forceall:true
EOF
```

## 6. 修复后的验证

### 6.1 只读挂载检查 shell 是否可读

```bash
guestfish --ro -a NaCC.qcow2 -m /dev/sda1:/ <<'EOF'
ll /bin/sh
ll /bin/bash
statns /bin/sh
EOF
```

本次结果：

- `/bin/sh`
- `/bin/bash`

均可正常读取。

### 6.2 再做一次只读 fsck 状态检查

```bash
guestfish --ro -a NaCC.qcow2 <<'EOF'
run
fsck ext4 /dev/sda1
EOF
```

本次返回值：

- `0`

说明 ext4 当前是一致的。

## 7. 什么时候需要放弃修复、直接重建

如果出现以下情况，建议直接重建磁盘：

- `e2fsck` 无法完成
- 修后仍然无法读取 `/bin/sh`
- guest 启动后仍持续出现 `EXT4-fs error`
- Docker / rootfs 中关键文件已经大面积损坏

重建方式：

```bash
cd /home/link/NaCC
make linux-modules
make rootfs-setup
```

注意：

- `rootfs-setup` 依赖 `disk`
- 会重新创建 `NaCC.qcow2`
- 来宾系统中的现有数据会丢失

## 8. 以后避免再次发生

最重要的约束：

- **只要 QEMU 还在运行，就不要执行会通过 `qemu-nbd` 改写 `NaCC.qcow2` 的 Make 目标**

尤其避免：

- `make disk`
- `make rootfs`
- `make rootfs-setup`
- `make modules-update`
- `make modules-update-wrapper`

此外：

- 结束实验时尽量先在 guest 里 `sync` 或 `poweroff`
- 不要把 `pkill qemu-system-riscv64` 当作常规关机手段
- 若要做高风险实验，先备份 `NaCC.qcow2`

## 9. 当前结论

本次故障是：

- `NaCC.qcow2` 内部 ext4 损坏

不是：

- `qcow2` 容器层损坏
- Linux / OpenSBI / Agent 二进制本身损坏

本次修复后：

- ext4 一致性检查通过
- 关键 shell 文件可读
- 可继续重新启动 VM 验证运行态是否完全恢复
