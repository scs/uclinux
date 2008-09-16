VPATH = linux

CPPFLAGS += -Ilinux -DFTPLIB_DEFMODE=FTPLIB_PORT -D_REENTRANT

TARGETS-y = libftp.a
TARGETS-$(CONFIG_FMT_USE_FDPIC_ELF) += libftp.so

all: $(TARGETS-y)

%.lo: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -fPIC -c -o $@ $<

libftp.so: ftplib.lo
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -fPIC -shared -Wl,-soname,libftp.so.3 -o $@ $^

libftp.a: ftplib.o
	$(AR) rc $@ $^

DESTDIR =
LIBDIR = /usr/lib
INCLUDEDIR = /usr/include
install: $(TARGETS-y)
	install -m 644 -D linux/ftplib.h $(DESTDIR)$(INCLUDEDIR)/ftplib.h
	install -m 644 -D libftp.a $(DESTDIR)$(LIBDIR)/libftp.a
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
	install -m 755 -D libftp.so $(DESTDIR)$(LIBDIR)/libftp.so.3
	ln -sf libftp.so.3 $(DESTDIR)$(LIBDIR)/libftp.so
endif

clean:
	rm -f *.o *.lo libftp.so libftp.a

.PHONY: all clean install
