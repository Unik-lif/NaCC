# The main Makefile for Native Confidential Container project
# This Makefile is used to build the project and its components
# It includes the necessary sub-makefiles for different components
# SPDX-License-Identifier: Apache-2.0


# For Linux Debug
#  make ARCH=riscv O=/home/link/Desktop/NaCC/riscv-linux CROSS_COMPILE=/home/link/Desktop/NaCC/riscv-tools/bin/riscv64-unknown-linux-gnu- -j128

CONFIGS := config

# RISCV Toolchain should be installed and available
TOOLCHAIN_GITHUB_REPO := https://github.com/riscv-collab/riscv-gnu-toolchain.git
TOOLCHAIN_DIR := riscv-gnu-toolchain
TOOLCHAIN_BRANCH := 2025.05.30
TOOLCHAIN_WRKDIR := riscv-tools

# We use customized QEMU, Linux, and OpenSBI
# So we will simply compile here
QEMU_SRCDIR := qemu
QEMU_WRKDIR := riscv-qemu

QEMU_PLATFORM := generic

QEMU_DEMO := qemu-demo

LINUX_SRCDIR := linux
LINUX_WRKDIR := riscv-linux
LINUX_MODULES := riscv-linux-modules

AGENT_SRCDIR := agent


OPENSBI_SRCDIR := opensbi


OPENSBI_PLATFORM := generic

# The Disk image with Ubuntu rootfs will be built from scratch
DISK := NaCC

# The Ubuntu rootfs tarball will be downloaded from the official source
TARBALL := Ubuntu-Jammy-rootfs.tar.gz


# Make Tagerts will be given here
.PHONY: all
all: tools qemu opensbi linux linux-modules disk rootfs

.PHONY: update-all
update-all: qemu opensbi linux linux-modules

.PHONY: tools
tools:
	@echo "\033[0;33mToolchain Detecting...\033[0m"
	@if [ -d "$(TOOLCHAIN_DIR)" ]; then \
		echo "Toolchain already exists at $(TOOLCHAIN_DIR)"; \
	else \
		echo "Cloning RISC-V toolchain version $(TOOLCHAIN_BRANCH)..."; \
		git clone --branch $(TOOLCHAIN_BRANCH) $(TOOLCHAIN_GITHUB_REPO) $(TOOLCHAIN_DIR); \
		(cd $(TOOLCHAIN_DIR) && \
		git rm qemu && \
		git submodule update --init --recursive); \
	fi

	@if [ -d "$(TOOLCHAIN_WRKDIR)/bin" ]; then \
		echo "Toolchain already installed at $(abspath $(TOOLCHAIN_WRKDIR)), skipping build"; \
	else \
		mkdir -p $(TOOLCHAIN_WRKDIR) && \
		(cd $(TOOLCHAIN_DIR) && \
		make clean && \
		./configure --prefix=$(abspath $(TOOLCHAIN_WRKDIR)) && \
		make linux -j $$(nproc)) ; \
	fi
	@echo "\033[0;32mToolchain installed to $(TOOLCHAIN_WRKDIR)\033[0m"; \
	

# qemu will run in the host environment, so qemu will not depend on the tools, but the linux will
.PHONY: qemu
qemu: 
	@echo "\033[0;33mBuilding QEMU...\033[0m"
	@rm -rf $(QEMU_WRKDIR)
	@mkdir -p $(QEMU_WRKDIR)
	@(cd $(QEMU_SRCDIR) && \
	./configure --target-list=riscv64-softmmu,riscv64-linux-user --enable-debug --prefix=$(abspath $(QEMU_WRKDIR)) && \
	make -j $$(nproc) && \
	make install && \
	echo "\033[0;32mQEMU built successfully to $(QEMU_WRKDIR)\033[0m")


.PHONY: linux-menuconfig
linux-menuconfig: 
# First get menuconfig .config
	@echo "\033[0;33mConfiguring Linux kernel...\033[0m"
	@rm -rf $(LINUX_WRKDIR)
	@mkdir -p $(LINUX_WRKDIR)
	@make -C $(abspath $(LINUX_SRCDIR)) ARCH=riscv mrproper
	@make -C $(abspath $(LINUX_SRCDIR)) ARCH=riscv clean
	make ARCH=riscv -C $(abspath $(LINUX_SRCDIR)) O=$(abspath $(LINUX_WRKDIR)) CROSS_COMPILE=$(abspath $(TOOLCHAIN_WRKDIR))/bin/riscv64-unknown-linux-gnu- menuconfig
	@echo "\033[0;32mLinux kernel configuration saved to $(LINUX_WRKDIR)/.config\033[0m"
	@cp $(LINUX_WRKDIR)/.config $(CONFIGS)/linux_config

.PHONY: kernel_switch
kernel_switch:
	$(MAKE) linux-menuconfig
	$(MAKE) linux
	$(MAKE) linux-modules 
	$(MAKE) modules-update
	$(MAKE) launch

.PHONY: linux
linux: 
	@echo "\033[0;33mBuilding Linux kernel...\033[0m"
	@rm -rf $(LINUX_WRKDIR)
	@mkdir -p $(LINUX_WRKDIR)
	@make -C $(abspath $(LINUX_SRCDIR)) ARCH=riscv mrproper
	@make -C $(abspath $(LINUX_SRCDIR)) ARCH=riscv clean
	@cp $(CONFIGS)/linux_config $(LINUX_WRKDIR)/.config
	make ARCH=riscv -C $(abspath $(LINUX_SRCDIR)) O=$(abspath $(LINUX_WRKDIR)) CROSS_COMPILE=$(abspath $(TOOLCHAIN_WRKDIR))/bin/riscv64-unknown-linux-gnu- olddefconfig
	make ARCH=riscv -C $(abspath $(LINUX_SRCDIR)) O=$(abspath $(LINUX_WRKDIR)) CROSS_COMPILE=$(abspath $(TOOLCHAIN_WRKDIR))/bin/riscv64-unknown-linux-gnu- -j $$(nproc)
	@(cd $(LINUX_SRCDIR) && \
	python scripts/clang-tools/gen_compile_commands.py -d $(abspath $(LINUX_WRKDIR)) -o compile_commands.json)


.PHONY: linux-modules
linux-modules: 
	@rm -rf $(LINUX_MODULES)
	@rm -rf kernel-modules.tar.gz
	@mkdir -p $(LINUX_MODULES)
	make ARCH=riscv -C $(abspath $(LINUX_SRCDIR)) O=$(abspath $(LINUX_WRKDIR)) CROSS_COMPILE=$(abspath $(TOOLCHAIN_WRKDIR))/bin/riscv64-unknown-linux-gnu- modules_install INSTALL_MOD_PATH=$(abspath $(LINUX_MODULES))
	@echo "\033[0;32mLinux kernel modules installed to $(LINUX_MODULES)\033[0m"
	@(cd $(LINUX_MODULES)/lib/modules && \
	tar -cf kernel-modules.tar --exclude='kernel-modules.tar' . && \
	gzip kernel-modules.tar)
	@mv $(LINUX_MODULES)/lib/modules/kernel-modules.tar.gz .


.PHONY: linux-update
linux-update: linux linux-modules modules-update final-image

.PHONY: agent-update
agent-update: agent final-image

.PHONY: agent
agent: 
	@echo "\033[0;33mBuilding Agent...\033[0m"
	@make -C $(abspath $(AGENT_SRCDIR)) CROSS_COMPILE=$(abspath $(TOOLCHAIN_WRKDIR))/bin/riscv64-unknown-elf- clean
	@make -C $(abspath $(AGENT_SRCDIR)) CROSS_COMPILE=$(abspath $(TOOLCHAIN_WRKDIR))/bin/riscv64-unknown-elf- all
	@make -C $(abspath $(AGENT_SRCDIR)) CROSS_COMPILE=$(abspath $(TOOLCHAIN_WRKDIR))/bin/riscv64-unknown-elf- objdump
	@echo "\033[0;32mAgent built successfully\033[0m"


.PHONY: agent-update
agent-update: agent final-image


.PHONY: final-image
final-image: 
	@echo "\033[0;33mBuilding final image...\033[0m"
	@rm -f final_image.bin
	@python3 pack_final_image.py $(abspath $(LINUX_WRKDIR)/arch/riscv/boot/Image) $(abspath $(AGENT_SRCDIR))/agent.bin final_image.bin
	@chmod +x final_image.bin
	@echo "\033[0;32mFinal image created at root directory\033[0m"

.PHONY: opensbi
opensbi: 
	@echo "\033[0;33mBuilding OpenSBI...\033[0m"
	@make -C $(abspath $(OPENSBI_SRCDIR)) clean
	@(cd $(OPENSBI_SRCDIR) && \
	bear -- make PLATFORM=$(OPENSBI_PLATFORM) CROSS_COMPILE=$(abspath $(TOOLCHAIN_WRKDIR))/bin/riscv64-unknown-linux-gnu- all -j $$(nproc))
	


# Guidance from https://github.com/carlosedp/riscv-bringup/tree/master/Qemu
.PHONY: disk
disk: tools
	@echo "\033[0;33mBuilding disk image...\033[0m"
	@rm -rf $(DISK).qcow2
	@sudo umount rootfs | true
	@sudo rm -rf rootfs
	@$(QEMU_WRKDIR)/bin/qemu-img create -f qcow2 $(DISK).qcow2 30G
	@sudo modprobe nbd max_part=16
	@sudo $(QEMU_WRKDIR)/bin/qemu-nbd -d /dev/nbd0
	@sudo $(QEMU_WRKDIR)/bin/qemu-nbd -c /dev/nbd0 $(DISK).qcow2
	@echo "label: dos\nlabel-id: 0x17527589\ndevice: /dev/nbd0\nunit: sectors\n\n/dev/nbd0p1 : start=2048, type=83, bootable" | sudo sfdisk /dev/nbd0
	@sudo mkfs.ext4 /dev/nbd0p1
	@sudo e2label /dev/nbd0p1 rootfs
	@mkdir rootfs
	@sudo mount /dev/nbd0p1 rootfs
	@echo "\033[0;32mDisk image created at disk/disk.qcow2\033[0m"


# The TarBall here won't be changed by modifying the linux configuration
# In fact the linux modification typically will not be reflected in the kernel modules 
.PHONY: rootfs
rootfs:
	@echo "\033[0;33mBuild Ubuntu rootfs...\033[0m"
	@sudo tar vxf $(TARBALL) -C rootfs
	@sudo mkdir -p rootfs/lib/modules
	@sudo tar zxvf kernel-modules.tar.gz -C rootfs/lib/modules
	@sudo umount rootfs | true
	@sudo $(QEMU_WRKDIR)/bin/qemu-nbd -d /dev/nbd0


.PHONY: modules-update
modules-update:
	@sudo modprobe nbd max_part=16
	@sudo $(QEMU_WRKDIR)/bin/qemu-nbd -c /dev/nbd0 $(DISK).qcow2
	@sudo mount /dev/nbd0p1 rootfs
	@sudo rm -rf rootfs/lib/modules
	@sudo mkdir -p rootfs/lib/modules
	@sudo tar zxvf kernel-modules.tar.gz -C rootfs/lib/modules
	@sudo umount rootfs
	@sudo $(QEMU_WRKDIR)/bin/qemu-nbd -d /dev/nbd0


.PHONY: launch
launch:
	@echo "\033[0;33mLaunching QEMU...\033[0m"
	@if [ "$(DEBUG)" = "1" ]; then \
		DEBUG_OPTS="-S -s"; \
	else \
		DEBUG_OPTS=""; \
	fi; \
	gdb --args $(QEMU_WRKDIR)/bin/qemu-system-riscv64 \
		-machine virt \
		-cpu rv64,sv39=on \
		-smp 4 \
		-nographic \
		-m 5G \
		-bios $(abspath $(OPENSBI_SRCDIR))/build/platform/generic/firmware/fw_jump.bin \
		-kernel final_image.bin \
		-append "root=/dev/vda1 rw console=ttyS0 memmap=1G\$$0x180000000" \
		-drive file=$(DISK).qcow2,format=qcow2,id=hd0,if=none \
		-device virtio-blk-device,drive=hd0 \
		-netdev user,id=net0,hostfwd=tcp::2222-:22 \
		-device virtio-net-device,netdev=net0 \
		$$DEBUG_OPTS



.PHONY: debug-qemu
debug-qemu:
	@echo "\033[0;33mDebugging QEMU...\033[0m"
	@(cd $(QEMU_DEMO) && \
	make clean && \
	make)
	@gdb --args $(QEMU_WRKDIR)/bin/qemu-system-riscv64 \
		-machine virt \
		-cpu rv64,sv39=on \
		-nographic \
		-bios clear_opensbi/build/platform/generic/firmware/fw_jump.bin \
		-kernel qemu-demo/$(TEST) \
		-d in_asm,op,exec,op_opt -D log.txt \
		

# agent-test is used to test the agent in the QEMU environment
# the agent.bin will start at the 0x80200000 like linux
# but in general agent.bin will be attached with the linux kernel
#
# Please make sure we've changed the agent.bin to the correct address
.PHONY: agent-test
agent-test:
	@echo "\033[0;33mLaunching QEMU...\033[0m"
	@if [ "$(DEBUG)" = "1" ]; then \
		DEBUG_OPTS="-S -s"; \
	else \
		DEBUG_OPTS=""; \
	fi; \
	$(QEMU_WRKDIR)/bin/qemu-system-riscv64 \
		-machine virt \
		-cpu rv64,sv39=on \
		-nographic \
		-m 8G \
		-bios $(abspath $(OPENSBI_SRCDIR))/build/platform/generic/firmware/fw_jump.bin \
		-kernel $(abspath $(AGENT_SRCDIR))/agent.bin \
		$$DEBUG_OPTS


.PHONY: debug-qemu-gdb
debug-qemu-gdb:
	@echo "\033[0;33mLaunching GDB...\033[0m"
	@$(TOOLCHAIN_WRKDIR)/bin/riscv64-unknown-linux-gnu-gdb -x $(CONFIGS)/a.gdbinit

.PHONY: gdb
gdb:
	@echo "\033[0;33mLaunching GDB...\033[0m"
	@$(TOOLCHAIN_WRKDIR)/bin/riscv64-unknown-linux-gnu-gdb -x $(CONFIGS)/.gdbinit


# SSH Link to the RISCV-VM
.PHONY: vm
vm:
	ssh -p 2222 root@localhost -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null


.PHONY: dump
dump:
	@$(TOOLCHAIN_WRKDIR)/bin/riscv64-unknown-linux-gnu-objdump -d $(LINUX_WRKDIR)/vmlinux > kernel_dump.txt


.PHONY: shallow-clean
shallow-clean: 
	@echo "\033[0;33mPerforming shallow clean...\033[0m"
	@rm -rf $(QEMU_WRKDIR) $(LINUX_WRKDIR) $(LINUX_MODULES) kernel-modules.tar.gz
	@(cd opensbi && \
		make clean && \
		rm -rf build)


.PHONY: deep-clean
deep-clean: shallow-clean
	@echo "\033[0;33mPerforming deep clean... Including Disk and rootfs\033[0m"
	@sudo umount rootfs | true
	@sudo rm -rf $(DISK).qcow2 rootfs
	
