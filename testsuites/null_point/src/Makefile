# Makefile for null point check test

CC	= bfin-uclinux-gcc
CFLAGS += -Wl,-elf2flt

SRCS	= null_point.c
TARGETS	= $(patsubst %.c,%,$(SRCS))

all: $(TARGETS)

clean:
	rm -f $(TARGETS)
	rm -f $(wildcard *.gdb)
