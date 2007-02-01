CFLAGS += -Wall

all: rtc_test 

romfs:
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_RTC /bin/rtc_test

clean:
	rm -f *.elf *.gdb *.o rtc_test

.PHONY: all clean romfs
