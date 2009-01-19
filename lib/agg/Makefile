VER = agg-2.5

CONF_OPTS = \
	--without-x \
	--disable-examples \
	$(call USE_ENABLE,LIB_FREETYPE,freetype)

export ac_cv_path_SDL_CONFIG = no

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libagg.so.2 /usr/lib/libagg.so.2
