
all: rtc_test 

rtc_test: rtc_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ rtc_test.c $(LDLIBS) 
romfs:
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_RTC /bin/rtc_test
clean:
	rm -f *.elf *.gdb *.o rtc_test

