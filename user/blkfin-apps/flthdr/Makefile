EXEC = flthdr
OBJS = flthdr.o

CPPFLAGS += -DSTDC_HEADERS=1 -DHAVE_FCNTL_H=1 -DHAVE_UNISTD_H=1 -DHAVE_VPRINTF=1  -DTARGET_bfin

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

rcp.o: flthdr.c flat.h

