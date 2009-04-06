VER = SDL_gfx-2.0.18

export ac_cv_path_SDL_CONFIG = $(CROSS_COMPILE)sdl-config
CONF_OPTS = \
	--disable-mmx

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libSDL_gfx.so.0 /usr/lib/libSDL_gfx.so.0
