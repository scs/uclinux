CC=bfin-uclinux-gcc
LDFLAGS=-Wl,-elf2flt -static
CPPFLAGS=-Iinclude
SRCS=$(wildcard *.c)
TARGETS=$(patsubst %.c,%,$(SRCS))

all: $(TARGETS)

$(TARGETS): $(SRCS)
	$(CC) $(CPPFLAGS) $@.c $(LDFLAGS) -o $@

clean:
	rm -rf $(TARGETS)
	rm -rf $(patsubst %,%.gdb,$(TARGETS))
