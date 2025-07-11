.section .text
.global _start
_start:
    li t0, 10
    li t1, 20
    add t2, t0, t1     # t2 = t0 + t1
    mul t3, t0, t1     # t3 = t0 * t1
    xor t4, t2, t3     # t4 = t2 ^ t3
    j .                # 死循环，防止退出
