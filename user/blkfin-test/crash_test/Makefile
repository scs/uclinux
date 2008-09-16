EXEC = crash_test traps_test

all: $(EXEC)

crash_test:
	$(CC) $(LDFLAGS) crash_test.c -o $@ $(LDLIBS)

traps_test:
	$(CC) $(LDFLAGS) traps_test.c -o $@ $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_PANICTEST /bin/crash_test
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_TRAPSTEST /bin/traps_test

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
 
