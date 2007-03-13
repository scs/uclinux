DESTDIR=$(TEMPDIR)
CFLAGS += -fno-strict-aliasing -ffast-math -mfast-fp 
CFLAGS += -I$(STAGEDIR)/usr/local/include
LDFLAGS += -L$(STAGEDIR)/usr/local/lib
LINPHONE_FLAGS+=--enable-portaudio=no
LINPHONE_FLAGS+=--enable-gnome_ui=no
LINPHONE_FLAGS+=--disable-video
LINPHONE_FLAGS+=--disable-manual
LINPHONE_FLAGS+=--disable-shared
LINPHONE_FLAGS+=--enable-static
LINPHONE_FLAGS+=--disable-glib
LINPHONE_FLAGS+=--enable-ipv6=no
LINPHONE_FLAGS+=--with-osip=$(TEMPDIR)
LINPHONE_FLAGS+=PKG_CONFIG_PATH=$(TEMPDIR)/lib/pkgconfig:$(STAGEDIR)/usr/lib/pkgconfig

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
		LIBS="$(LDLIBS)"

clean:
	rm -rf build
