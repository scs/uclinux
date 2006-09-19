DESTDIR=$(TEMPDIR)
CFLAGS += -fno-strict-aliasing
CFLAGS += -I$(DESTDIR)/include/readline
CFLAGS += -I$(UCLDIR)/lib/ncurses/include/
LDFLAGS +=-L$(UCLDIR)/lib/ncurses/lib/
LINPHONE_FLAGS+=--enable-portaudio=no
LINPHONE_FLAGS+=--enable-gnome_ui=no
LINPHONE_FLAGS+=--disable-video
LINPHONE_FLAGS+=--disable-manual
LINPHONE_FLAGS+=--disable-shared
LINPHONE_FLAGS+=--enable-static
LINPHONE_FLAGS+=--disable-glib
LINPHONE_FLAGS+=--with-osip=$(TEMPDIR)
LINPHONE_FLAGS+=--with-speex=$(TEMPDIR)
LINPHONE_FLAGS+=--with-readline=$(TEMPDIR)
LINPHONE_FLAGS+=PKG_CONFIG_PATH=$(TEMPDIR)/lib/pkgconfig


all:	Makefile
	make install 

Makefile:
	./configure --host=bfin-uclinux --prefix=$(TEMPDIR) --with-real-prefix=$(DESTDIR) $(LINPHONE_FLAGS) CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" LIBS="$(LDLIBS)" CC="$(CC)"
 

clean:
	make clean
	make -i distclean
	find . -name '*.gdb' -print0 | xargs -0 rm -f
	
