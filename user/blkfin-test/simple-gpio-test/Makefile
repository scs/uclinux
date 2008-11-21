CFLAGS += -Wall

all: simple-gpio-game simple-gpio-test simple-gpio-watch

clean:
	rm -f simple-gpio-game simple-gpio-test simple-gpio-watch *.o *.gdb

romfs:
	$(ROMFSINST) /bin/simple-gpio-game
	$(ROMFSINST) /bin/simple-gpio-test
	$(ROMFSINST) /bin/simple-gpio-watch

.PHONY: all clean romfs
