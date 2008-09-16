CFLAGS += -Wall
EXEC = ad5304_test

all: $(EXEC)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
