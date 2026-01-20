set confirm off
set architecture riscv:rv64
target remote:1234
add-symbol-file opensbi/build/platform/generic/firmware/fw_jump.elf 0x80000000
# before MMU, add-symbol-file riscv-linux/vmlinux 0x80202000 -s .head.text 0x80200000 -s .init.text 0x80c00000 -s .rodata 0x81000000
add-symbol-file riscv-linux/vmlinux
add-symbol-file agent/agent.elf
set disassemble-next-line auto
