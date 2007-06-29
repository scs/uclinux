# Makefile for dma_memcpy test

CC	= bfin-uclinux-gcc
CFLAGS += -Wl,-elf2flt

SRCS	= dmacopy.c
TARGETS	= $(patsubst %.c,%,$(SRCS))

all: $(TARGETS)

clean:
	rm -f $(TARGETS)
	rm -f $(wildcard *.gdb)
