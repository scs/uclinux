
CFLAGS = -mabi=64 -G 0 -mlong-calls -mno-abicalls -fno-pic -msoft-float -ffreestanding -O2
LDFLAGS = -melf64btsmip -nostdlib

OBJS = start.o flasher.o


all: flasher

flasher: $(OBJS)
	mips-linux-ld $(LDFLAGS) -T flasher.ld -static -o flasher $(OBJS)

%.o: %.S
	mips-linux-gcc $(CFLAGS) -c $<

%.o: %.c
	mips-linux-gcc $(CFLAGS) -c $<

boot.elf: boot.bin
	mips-linux-ld -Tdata=0x00080000 -o boot.elf -b binary boot.bin

clean:
	rm -f flasher *.o boot.elf

