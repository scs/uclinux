EXEC = edn

ifndef INLINE
OBJS = edn.o linux.o
else
OBJS = linux.o
CFLAGS += -DINLINE
endif

all: $(EXEC)
LDLIBS += -lrt

sysinfo.c:
	./sysinfo.sh $(CC) $(CFLAGS) $(LDFLAGS) $(LDLIBS)

$(EXEC): sysinfo.c $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) -lm $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	rm -f *.o $(EXEC) *.gdb sysinfo.c

