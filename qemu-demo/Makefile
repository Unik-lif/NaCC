CROSS = ../riscv-tools/bin/riscv64-unknown-elf
AS = $(CROSS)-as
LD = $(CROSS)-ld
OBJCOPY = $(CROSS)-objcopy

TEXT_BASE = 0x80000000
LDFLAGS = -Ttext=$(TEXT_BASE)

TARGETS = cal ecall illegal_csr illegal_mem

all: $(TARGETS:=.bin)

%.o: %.S
	$(AS) -o $@ $<

%.elf: %.o
	$(LD) $(LDFLAGS) -o $@ $<

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f *.o *.elf *.bin
