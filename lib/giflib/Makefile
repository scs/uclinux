VER = giflib-4.1.6

CONF_OPTS = \
	--disable-rle

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libgif.so.4 /usr/lib/libgif.so.4
