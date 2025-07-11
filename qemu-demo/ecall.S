.section .text
.global _start
_start:
    li a7, 123         # syscall number
    ecall              # 触发陷入（Machine mode trap）
    j .                # 等待 trap handler 处理
