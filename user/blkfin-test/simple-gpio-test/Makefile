CFLAGS += -Wall

all: simple-gpio-game simple-gpio-test

clean:
	rm -f simple-gpio-game simple-gpio-test *.o *.gdb

romfs:
	$(ROMFSINST) /bin/simple-gpio-game
	$(ROMFSINST) /bin/simple-gpio-test

.PHONY: all clean romfs
