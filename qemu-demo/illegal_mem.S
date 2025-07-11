.section .text
.global _start
_start:
    li t0, 0xdeadbeef
    lw t1, 0(t0)       # 访问非法物理地址
    j .
