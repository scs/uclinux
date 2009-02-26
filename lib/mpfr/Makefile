VER = mpfr-2.4.1

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libmpfr.so.1 /usr/lib/libmpfr.so.1
