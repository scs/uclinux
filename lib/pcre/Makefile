VER = pcre-7.9

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libpcre.so.0 /usr/lib/libpcre.so.0
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libpcreposix.so.0 /usr/lib/libpcreposix.so.0
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libpcrecpp.so.0 /usr/lib/libpcrecpp.so.0
