VER = libmad-0.15.1b

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libmad.so.0 /usr/lib/
