EXEC = msgtool shmtool semtool
OBJS = msgtool.o shmtool.o semtool.o

all: $(EXEC)

msgtool: msgtool.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ msgtool.o $(LDLIBS)

semtool: semtool.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ semtool.o $(LDLIBS)

shmtool: shmtool.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ shmtool.o $(LDLIBS)

clean:
	rm -f *.o $(EXEC) *.gdb *~ *.elf

romfs:
	$(ROMFSINST) /bin/msgtool
	$(ROMFSINST) /bin/shmtool
	$(ROMFSINST) /bin/semtool
