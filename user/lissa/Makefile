CFLAGS += -Wall
LDLIBS += -lm

all: lissa

romfs:
	$(ROMFSINST) /bin/lissa

clean:
	-rm -f lissa *.elf *.gdb *.o

.PHONY: all clean romfs
