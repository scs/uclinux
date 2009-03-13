VER = freetype-2.3.9
URL = http://downloads.sourceforge.net/sourceforge/freetype/$(VER).tar.bz2

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libfreetype.so.6 /usr/lib/libfreetype.so.6
