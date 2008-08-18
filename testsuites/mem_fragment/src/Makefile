CC	= bfin-uclinux-gcc
CFLAGS += -Wl,-elf2flt

SRCS	= mkfragment.c
TARGETS	= $(patsubst %.c,%,$(SRCS))

all: $(TARGETS)

clean:
	rm -f $(TARGETS)
	rm -f $(wildcard *.gdb)
