
bindir=/bin

PATHDEF_CP = -DPATH_CP=\"$(bindir)/cp\"
PATHDEF_RSH = -DPATH_RSH=\"$(bindir)/rsh\"

EXEC = rcp
OBJS = rcp.o util.o

CPPFLAGS += -DHAVE_CONFIG_H $(PATHDEF_CP) $(PATHDEF_RSH) -I.. -I../include

LDLIBS += -L../libinetutils -linetutils

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

rcp.o: rcp.c ../config.h ../include/confpaths.h extern.h
util.o: util.c ../config.h ../include/confpaths.h \
  extern.h
