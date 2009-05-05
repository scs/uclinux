CFLAGS += -Wall

EXEC = crash_test traps_test

all: $(EXEC)

romfs:
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_PANICTEST /bin/crash_test
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_TRAPSTEST /bin/traps_test

clean:
	rm -f $(EXEC) *.elf *.gdb *.o *~
