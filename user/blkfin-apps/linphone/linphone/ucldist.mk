DESTDIR=$(TEMPDIR)
CFLAGS += -fno-strict-aliasing
CFLAGS += -I$(ROOTDIR)/lib/readline/DESTDIR/usr/include/readline
CFLAGS += -I$(ROOTDIR)/lib/ncurses/include/
LDFLAGS += -L$(ROOTDIR)/lib/ncurses/lib/
CFLAGS += -I$(ROOTDIR)/lib/speex/DESTDIR/usr/include
LDFLAGS += -L$(ROOTDIR)/lib/speex/DESTDIR/usr/lib
LINPHONE_FLAGS+=--enable-portaudio=no
LINPHONE_FLAGS+=--enable-gnome_ui=no
LINPHONE_FLAGS+=--disable-video
LINPHONE_FLAGS+=--disable-manual
LINPHONE_FLAGS+=--disable-shared
LINPHONE_FLAGS+=--enable-static
LINPHONE_FLAGS+=--disable-glib
LINPHONE_FLAGS+=--with-osip=$(TEMPDIR)
LINPHONE_FLAGS+=--with-speex=$(ROOTDIR)/lib/speex/DESTDIR/usr
LINPHONE_FLAGS+=--with-readline=$(ROOTDIR)/lib/readline/DESTDIR/usr
LINPHONE_FLAGS+=PKG_CONFIG_PATH=$(TEMPDIR)/lib/pkgconfig:$(ROOTDIR)/lib/speex/DESTDIR/usr/lib/pkgconfig:$(ROOTDIR)/lib/readline/DESTDIR/usr/lib/pkgconfig

PKG_CONFIG=/usr/bin/pkg-config


all: build/Makefile
	$(MAKE) -C build install DESTDIR=$(DESTDIR)

build/Makefile:
	touch *
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure \
		--host=$(CONFIGURE_HOST) \
		--prefix=/usr \
		$(LINPHONE_FLAGS) \
		CFLAGS="$(CFLAGS)" \
		LDFLAGS="$(LDFLAGS)" \
		LIBS="$(LDLIBS)" \
		CC="$(CC) "

clean:
	rm -rf build
