VER = libpng-1.2.36
URL = http://downloads.sourceforge.net/sourceforge/libpng/$(VER).tar.lzma

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libpng12.so.0 /usr/lib/libpng12.so.0
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libpng.so.3 /usr/lib/libpng.so.3
