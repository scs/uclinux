VER = libogg-1.1.3

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libogg.so.0 /usr/lib/libogg.so.0
