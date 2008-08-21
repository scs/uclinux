VER = libpng-1.2.31

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libpng12.so.0 /usr/lib/libpng12.so.0
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libpng.so.3 /usr/lib/libpng.so.3
