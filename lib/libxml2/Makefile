VER = libxml2-2.6.31

CONF_OPTS = \
	--without-python \
	$(call USE_ENABLE,LIB_ZLIB,zlib) \
	$(call USE_ENABLE,LIB_READLINE,readline) \
	$(call USE_ENABLE,LIB_READLINE,history)

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libxml2.so.2 /usr/lib/libxml2.so.2
