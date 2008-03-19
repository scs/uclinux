VER = lzo-2.02

CONF_OPTS = \
	$(CONFIGURE_SHARED_ENABLE)

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/liblzo2.so.2 /usr/lib/liblzo2.so.2
