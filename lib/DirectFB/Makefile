VER = DirectFB-1.2.6

USE_ENABLE = $(shell test "$(CONFIG_$(1))" = "y" && echo "--enable-$(2)" || echo "--disable-$(2)")

CONF_OPTS = \
	--with-tests \
	--with-gfxdrivers=none \
	--disable-multi \
	--enable-fbdev \
	--disable-x11 \
	--disable-vnc \
	$(call USE_ENABLE,LIB_LIBSDL,sdl) \
	$(call USE_ENABLE,LIB_LIBJPEG,jpeg) \
	$(call USE_ENABLE,LIB_ZLIB,zlib) \
	$(call USE_ENABLE,LIB_LIBPNG,png) \
	$(call USE_ENABLE,LIB_FREETYPE,freetype) \

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)

build-$(VER)/Makefile:
	# released tarballs contain a few generated files
	rm -f $(VER)/lib/*/build.h
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	SDL_CONFIG=$(STAGEDIR)/usr/bin/sdl-config \
	LIBPNG_CONFIG="$(PKG_CONFIG) libpng" \
	FREETYPE_CONFIG=$(STAGEDIR)/usr/bin/freetype-config \
	../$(VER)/configure $(CONFIGURE_OPTS) $(CONF_OPTS)

clean:
	rm -rf build*

LIB_VER = $(shell echo $(patsubst DirectFB-%,%,$(VER)) | cut -d. -f1,2)
romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libdirect-$(LIB_VER).so.0 /usr/lib/libdirect-$(LIB_VER).so.0
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libdirectfb-$(LIB_VER).so.0 /usr/lib/libdirectfb-$(LIB_VER).so.0
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libfusion-$(LIB_VER).so.0 /usr/lib/libfusion-$(LIB_VER).so.0
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/directfb-$(LIB_VER)-0 /usr/lib/directfb-$(LIB_VER)-0
	find $(ROMFSDIR)/usr/lib/directfb-$(LIB_VER)-0 -type f -name '*.la' -print0 | xargs -0 rm -f

.PHONY: all clean romfs
