VER = flac-1.2.1

CONF_OPTS = --with-ogg=$(STAGEDIR)/usr

include $(ROOTDIR)/tools/autotools.mk

romfs:
ifneq ($(VER),flac-1.1.0)
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libFLAC.so.8 /usr/lib/libFLAC.so.8
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libFLAC++.so.6 /usr/lib/libFLAC++.so.6
endif
