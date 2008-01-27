CFLAGS += -Wall

LDLIBS += -lm

all: video_test

romfs:
	$(ROMFSINST) /bin/video_test

clean:
	rm -f video_test *.elf *.gdb *.o

.PHONY: all clean romfs
