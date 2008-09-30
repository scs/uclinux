CFLAGS += -Wall

all: watchdogd

romfs:
	$(ROMFSINST) -e CONFIG_USER_WATCHDOGD /bin/watchdogd
	$(ROMFSINST) -e CONFIG_USER_WATCHDOGD -a "watchdogd:unknown:/bin/watchdogd -f -s" /etc/inittab

clean:
	-rm -f watchdogd *.elf *.gdb *.o

.PHONY: all clean romfs
