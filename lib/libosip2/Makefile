VER = libosip2-3.1.0

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libosip2.so.3 /usr/lib/libosip2.so.3
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libosipparser2.so.3 /usr/lib/libosipparser2.so.3
