.section .text
.global _start
_start:
    .word 0xCCCC4273     # csrrs t0, 0xCCCC, zero （伪造的 CSR 指令）
    j .
