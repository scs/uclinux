
EXEC = rshd
OBJS = rshd.o

CPPFLAGS += -DHAVE_CONFIG_H -I.. -I../include

LDLIBS += -L../libinetutils -linetutils

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

rshd.o: rshd.c ../config.h ../include/confpaths.h
