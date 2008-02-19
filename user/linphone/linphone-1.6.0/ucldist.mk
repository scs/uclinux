DESTDIR=$(TEMPDIR)
CFLAGS += -fno-strict-aliasing -ffast-math -mfast-fp 
LINPHONE_FLAGS+=--enable-portaudio=no
LINPHONE_FLAGS+=--enable-gnome_ui=no
ifeq ($(CONFIG_USER_BFIN_LINPHONE_VIDEO),)
LINPHONE_FLAGS+=--disable-video
endif
LINPHONE_FLAGS+=--disable-manual
LINPHONE_FLAGS+=--disable-shared
LINPHONE_FLAGS+=--enable-static
LINPHONE_FLAGS+=--disable-glib
LINPHONE_FLAGS+=--enable-ipv6=no
LINPHONE_FLAGS+=--with-osip=$(TEMPDIR)
LINPHONE_FLAGS+=--with-sdl=$(STAGEDIR)/usr
LINPHONE_FLAGS+=PKG_CONFIG_PATH=$(TEMPDIR)/lib/pkgconfig:$(STAGEDIR)/usr/lib/pkgconfig

all: build/Makefile
	$(MAKE) -C build install DESTDIR=$(DESTDIR)

build/Makefile:
	touch *
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure $(CONFIGURE_OPTS) $(LINPHONE_FLAGS)

clean:
	rm -rf build

.PHONY: all clean
