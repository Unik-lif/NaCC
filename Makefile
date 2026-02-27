# The main Makefile for Native Confidential Container project
# This Makefile is used to build the project and its components
# It includes the necessary sub-makefiles for different components
# SPDX-License-Identifier: Apache-2.0


# For Linux Debug
#  make ARCH=riscv O=/home/link/NaCC/riscv-linux CROSS_COMPILE=/home/link/NaCC/riscv-tools/bin/riscv64-unknown-linux-gnu- -j128

CONFIGS := config

# RISCV Toolchain should be installed and available
TOOLCHAIN_GITHUB_REPO := git@github.com:riscv-collab/riscv-gnu-toolchain.git 
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

# Kernel release string used for naming (override via: make rootfs-setup version=...)
version ?= $(shell cat $(LINUX_WRKDIR)/include/config/kernel.release 2>/dev/null || \
  make -s -C $(abspath $(LINUX_SRCDIR)) O=$(abspath $(LINUX_WRKDIR)) ARCH=riscv kernelrelease 2>/dev/null || \
  echo unknown)


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

	@sudo apt-get install autoconf automake autotools-dev curl python3 python3-pip python3-tomli libmpc-dev libmpfr-dev libgmp-dev gawk build-essential bison flex texinfo gperf libtool patchutils bc zlib1g-dev libexpat-dev ninja-build git cmake libglib2.0-dev libslirp-dev sshpass
	
	@if [ -d "$(TOOLCHAIN_WRKDIR)/bin" ]; then \
		echo "Toolchain already installed at $(abspath $(TOOLCHAIN_WRKDIR)), skipping build"; \
	else \
		mkdir -p $(TOOLCHAIN_WRKDIR) && \
		(cd $(TOOLCHAIN_DIR) && \
		make clean && \
		./configure --prefix=$(abspath $(TOOLCHAIN_WRKDIR)) && \
		make && make linux -j $$(nproc)) ; \
	fi
	@echo "\033[0;32mToolchain installed to $(TOOLCHAIN_WRKDIR)\033[0m"; \
	

# qemu will run in the host environment, so qemu will not depend on the tools, but the linux will
.PHONY: qemu
qemu: 
	@echo "\033[0;33mBuilding QEMU...\033[0m"
	@rm -rf $(QEMU_WRKDIR)
	@mkdir -p $(QEMU_WRKDIR)
	@(cd $(QEMU_SRCDIR) && \
	rm compile_commands.json || true && \
	./configure --target-list=riscv64-softmmu,riscv64-linux-user --enable-debug --prefix=$(abspath $(QEMU_WRKDIR)) && \
	make -j $$(nproc) && \
	make install && \
	cp build/compile_commands.json compile_commands.json && \
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
linux-update: linux linux-modules modules-update final-image dump

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
agent-update: agent final-image dump-agent


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
	@$(TOOLCHAIN_WRKDIR)/bin/riscv64-unknown-linux-gnu-objdump -d $(OPENSBI_SRCDIR)/build/platform/generic/firmware/fw_jump.elf > opensbi.asm


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


.PHONY: rootfs-setup
rootfs-setup: disk
	@sudo tar vxf Ubuntu-Jammy-rootfs.tar.gz -C rootfs
	@sudo mkdir -p rootfs/lib/modules
	@sudo tar zxvf kernel-modules.tar.gz -C rootfs/lib/modules
	@sudo mkdir -p rootfs/boot/extlinux
	@sudo cp $(LINUX_WRKDIR)/arch/riscv/boot/Image rootfs/boot/vmlinuz-$(version)
	@printf '%b' \
		"menu title RISC-V Qemu Boot Options\n" \
		"timeout 100\n" \
		"default kernel-$(version)\n\n" \
		"label kernel-$(version)\n" \
		"\tmenu label Linux kernel-$(version)\n" \
		"\tkernel /boot/vmlinuz-$(version)\n" \
		"\tinitrd /boot/initrd.img-$(version)\n" \
		"\tappend earlyprintk rw root=/dev/vda1 rootwait rootfstype=ext4 LANG=en_US.UTF-8 console=ttyS0\n\n" \
		"label rescue-kernel-$(version)\n" \
		"\tmenu label Linux kernel-$(version) (recovery mode)\n" \
		"\tkernel /boot/vmlinuz-$(version)\n" \
		"\tinitrd /boot/initrd.img-$(version)\n" \
		"\tappend earlyprintk rw root=/dev/vda1 rootwait rootfstype=ext4 LANG=en_US.UTF-8 console=ttyS0 single\n" \
	| sudo tee rootfs/boot/extlinux/extlinux.conf >/dev/null
	@sudo chroot rootfs update-initramfs -k all -c
	@sudo umount rootfs
	@sudo $(QEMU_WRKDIR)/bin/qemu-nbd -d /dev/nbd0

# The TarBall here won't be changed by modifying the linux configuration
# In fact the linux modification typically will not be reflected in the kernel modules 
.PHONY: rootfs
rootfs: disk
	@echo "\033[0;33mBuild Ubuntu rootfs...\033[0m"
	@sudo tar vxf $(TARBALL) -C rootfs
	@sudo mkdir -p rootfs/lib/modules
	@sudo tar zxvf kernel-modules.tar.gz -C rootfs/lib/modules
	@sudo umount rootfs | true
	@sudo $(QEMU_WRKDIR)/bin/qemu-nbd -d /dev/nbd0


.PHONY: modules-update
modules-update:
	@sudo umount rootfs 2>/dev/null || true
	@sudo $(QEMU_WRKDIR)/bin/qemu-nbd -d /dev/nbd0 2>/dev/null || true
	@sudo modprobe nbd max_part=16
	@sudo $(QEMU_WRKDIR)/bin/qemu-nbd -c /dev/nbd0 $(DISK).qcow2
	@sleep 2
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
	if [ "$(QEMU_GDB)" = "1" ]; then \
		GDB_CMD="gdb --args"; \
	else \
		GDB_CMD=""; \
	fi; \
	$$GDB_CMD $(QEMU_WRKDIR)/bin/qemu-system-riscv64 \
		-machine virt \
		-cpu rv64,sv39=on \
		-smp 1 \
		-nographic \
		-m 5G \
		-bios $(abspath $(OPENSBI_SRCDIR))/build/platform/generic/firmware/fw_jump.bin \
		-kernel final_image.bin \
		-append "root=/dev/vda1 rw console=ttyS0 memmap=1025M\$$0x17ff00000, " \
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
	@chmod +x config/vm_link.sh
	@./config/vm_link.sh

.PHONY: vm-debug
vm-debug:
	sshpass -p riscv ssh -p 2222 root@localhost -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null

.PHONY: debug
debug:
	@chmod +x config/tmux-debug.sh
	@./config/tmux-debug.sh


# Logger: capture log output from named tmux panes (set by config/tmux-debug.sh)
# Usage: make logger          — saves QEMU + VM logs with timestamp
#        make logger LOG=name — saves with custom name prefix
LOG_DIR := logs
LOG ?= nacc

.PHONY: logger
logger:
	@mkdir -p $(LOG_DIR)
	@TIMESTAMP=$$(date +%Y%m%d_%H%M%S); \
	QEMU_PANE=$$(tmux list-panes -a -F "#{pane_id} #{pane_title}" 2>/dev/null | grep "nacc-qemu" | head -1 | awk '{print $$1}'); \
	VM_PANE=$$(tmux list-panes -a -F "#{pane_id} #{pane_title}" 2>/dev/null | grep "nacc-vm" | head -1 | awk '{print $$1}'); \
	if [ -z "$$QEMU_PANE" ]; then \
		echo "\033[0;31mError: Cannot find pane 'nacc-qemu'. Did you run 'make debug' first?\033[0m"; \
		exit 1; \
	fi; \
	QEMU_LOG=$(LOG_DIR)/$(LOG)_qemu_$$TIMESTAMP.log; \
	tmux capture-pane -t "$$QEMU_PANE" -p -S - > "$$QEMU_LOG"; \
	echo "\033[0;32mQEMU log saved to $$QEMU_LOG ($$(wc -l < "$$QEMU_LOG") lines)\033[0m"; \
	if [ -n "$$VM_PANE" ]; then \
		VM_LOG=$(LOG_DIR)/$(LOG)_vm_$$TIMESTAMP.log; \
		tmux capture-pane -t "$$VM_PANE" -p -S - > "$$VM_LOG"; \
		echo "\033[0;32mVM   log saved to $$VM_LOG ($$(wc -l < "$$VM_LOG") lines)\033[0m"; \
	fi

.PHONY: dump
dump:
	@rm -rf vmlinux.asm
	@$(TOOLCHAIN_WRKDIR)/bin/riscv64-unknown-linux-gnu-objdump -d $(LINUX_WRKDIR)/vmlinux > vmlinux.asm

.PHONY: dump-agent
dump-agent:
	@rm -rf agent.asm
	@$(TOOLCHAIN_WRKDIR)/bin/riscv64-unknown-elf-objdump -d $(AGENT_SRCDIR)/agent.elf > agent.asm

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
	
