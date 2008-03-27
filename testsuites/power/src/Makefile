# Makefile for null point check test

CC	= bfin-linux-uclibc-gcc

SRCS	= rtctest.c
TARGETS	= $(patsubst %.c,%,$(SRCS))

all: $(TARGETS)

clean:
	rm -f $(TARGETS)
