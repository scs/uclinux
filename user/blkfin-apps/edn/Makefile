EXEC = edn
OBJS = edn.o linux.o

all: $(EXEC)
LDLIBS += -lrt

sysinfo.c:
	./sysinfo.sh $(CC) $(CFLAGS) $(LDFLAGS) $(LDLIBS)

$(EXEC): sysinfo.c $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) -lm $(LDLIBS)

clean:
	rm -f *.o $(EXEC) *.gdb sysinfo.c

