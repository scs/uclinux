
LIBRARIES = libinetutils.a
OBJS = localhost.o malloc.o realloc.o xmalloc.o #\
	argcv.o cleansess.o daemon.o des_rw.o kcmd.o krcmd.o \
	setsig.o tftpsubs.o logwtmpko.o ttymsg.o \
	xstrdup.o xgetcwd.o utmp_init.o utmp_logout.o \
	daemon.o  stub_tgetent.o forkpty.o \
	revoke.o regex.o 

CPPFLAGS += -DHAVE_CONFIG_H -I../ -I../include

RANLIB = $(CROSS_COMPILE)ranlib

all: $(LIBRARIES)

$(LIBRARIES): $(OBJS)
	-rm -f $(LIBRARIES)
	$(AR) cru $(LIBRARIES) $(OBJS)
	$(RANLIB) $@

romfs:	;

clean:
	-rm -f $(LIBRARIES) *.o

argcv.o: argcv.c argcv.h
cleansess.o: cleansess.c ../config.h ../include/confpaths.h
daemon.o: daemon.c ../config.h ../include/confpaths.h
des_rw.o: des_rw.c ../config.h ../include/confpaths.h
forkpty.o: forkpty.c ../config.h ../include/confpaths.h
kcmd.o: kcmd.c ../config.h ../include/confpaths.h
krcmd.o: krcmd.c ../config.h ../include/confpaths.h
localhost.o: localhost.c ../config.h ../include/confpaths.h
logwtmpko.o: logwtmpko.c logwtmp.c ../config.h ../include/confpaths.h
malloc.o: malloc.c ../config.h ../include/confpaths.h
realloc.o: realloc.c ../config.h ../include/confpaths.h
regex.o: regex.c ../config.h ../include/confpaths.h ./regex.h
revoke.o: revoke.c ../config.h ../include/confpaths.h
setsig.o: setsig.c ../config.h ../include/confpaths.h
stub_tgetent.o: stub_tgetent.c
tftpsubs.o: tftpsubs.c ../config.h ../include/confpaths.h \
  ../include/arpa/tftp.h ../include/tftpsubs.h
ttymsg.o: ttymsg.c ../config.h ../include/confpaths.h
utmp_init.o: utmp_init.c ../config.h ../include/confpaths.h
utmp_logout.o: utmp_logout.c ../config.h ../include/confpaths.h
xgetcwd.o: xgetcwd.c ../config.h ../include/confpaths.h xalloc.h
xmalloc.o: xmalloc.c ../config.h ../include/confpaths.h gettext.h \
  xalloc.h
xstrdup.o: xstrdup.c ../config.h ../include/confpaths.h xalloc.h
