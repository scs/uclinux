CFLAGS += -Wall

all: gettimeofday_test 

romfs:
	$(ROMFSINST) -e CONFIG_USER_GETTIMEOFDAY_TEST /bin/gettimeofday_test

clean:
	rm -f *.elf *.gdb *.o rtc_test

.PHONY: all clean romfs
