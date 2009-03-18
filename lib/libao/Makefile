VER = libao-0.8.8

CONF_OPTS := \
	--disable-esd \
	--disable-arts \
	--without-x

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libao.so.2 /usr/lib/libao.so.2
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/ao/plugins-2 /usr/lib/ao/plugins-2
	rm -f $(ROMFSDIR)/usr/lib/ao/plugins-2/*.la
