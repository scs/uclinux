VER = SDL-1.2.13

CONF_OPTS = \
	--disable-arts \
	--disable-esd \
	--disable-pth \
	--disable-video-directfb \
	--disable-video-x11

include $(ROOTDIR)/tools/autotools.mk

# upstream's install targets lack dependencies on the things
# they install, so just decouple build/install steps
pre-build::
	$(MAKE) -C build-$(VER)

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libSDL-1.2.so.0 /usr/lib/libSDL-1.2.so.0
