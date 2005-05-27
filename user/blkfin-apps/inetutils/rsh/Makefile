
bindir=/bin

PATHDEF_RLOGIN = -DPATH_RLOGIN=\"$(bindir)/rlogin\"

EXEC = rsh
OBJS = rsh.o

CPPFLAGS += -DHAVE_CONFIG_H $(PATHDEF_RLOGIN) -I.. -I../include

LDLIBS += -L../libinetutils -linetutils

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

rsh.o: rsh.c ../config.h ../include/confpaths.h
