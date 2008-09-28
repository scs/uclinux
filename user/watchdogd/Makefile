CFLAGS += -Wall

EXEC = watchdogd

all: $(EXEC)

romfs:
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_WATCHDOGD /bin/$(EXEC)
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_WATCHDOGD -a "watchdogd:unknown:/bin/watchdogd -f -s" /etc/inittab

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

.PHONY: all clean romfs
