# Makefile for dma_memcpy test

CC	= bfin-uclinux-gcc
CFLAGS += -Wall -g
LDFLAGS += -Wl,-elf2flt

SRCS	= dmacopy.c
TARGETS	= $(patsubst %.c,%,$(SRCS))

all: $(TARGETS)

clean:
	rm -f $(TARGETS)
	rm -f $(wildcard *.gdb)
