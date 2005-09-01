
all:
	bfin-uclinux-gcc -o twitest twitest.c -Wl,-elf2flt
	cp twitest ../../romfs/bin

clean:
	rm -f twitest twitest.o twitest.gdb

