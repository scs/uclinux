
all: dpmc_test 

rtc_test: dpmc_test.c
	$(CC) $(LDFLAGS) -o $@ dpmc_test.c $(LDLIBS) 
romfs:
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_DPMC /bin/dpmc_test
clean:
	rm -f *.elf *.gdb *.o dpmc_test

