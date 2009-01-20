VER = DirectFB-1.2.7

export LIBPNG_CONFIG="$(PKG_CONFIG) libpng"

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

include $(ROOTDIR)/tools/autotools.mk

LIB_VER = $(shell echo $(patsubst DirectFB-%,%,$(VER)) | cut -d. -f1,2)
romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libdirect-$(LIB_VER).so.0 /usr/lib/libdirect-$(LIB_VER).so.0
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libdirectfb-$(LIB_VER).so.0 /usr/lib/libdirectfb-$(LIB_VER).so.0
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libfusion-$(LIB_VER).so.0 /usr/lib/libfusion-$(LIB_VER).so.0
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/directfb-$(LIB_VER)-0 /usr/lib/directfb-$(LIB_VER)-0
	find $(ROMFSDIR)/usr/lib/directfb-$(LIB_VER)-0 -type f -name '*.la' -print0 | xargs -0 rm -f
