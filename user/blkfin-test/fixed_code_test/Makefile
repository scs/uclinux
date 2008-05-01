ifeq ($(origin CC),default)
CC := bfin-uclinux-gcc
LDFLAGS += -elf2flt
endif

CFLAGS += -Wall
CPPFLAGS += -I.

TARGETS = fixed_code fixed_code_p

all: $(TARGETS)

fixed_code: fixed_code.o
fixed_code_p: fixed_code_p.o
fixed_code_p: LDLIBS += -lpthread

romfs:
	$(ROMFSINST) /bin/fixed_code
	$(ROMFSINST) /bin/fixed_code_p

clean:
	rm -f *.o *.gdb $(TARGETS)

.PHONY: all clean romfs
