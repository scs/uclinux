CFLAGS += -Wall

LDLIBS += -lm

all: video_test

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	rm -f video_test *.elf *.gdb *.o

.PHONY: all clean romfs
