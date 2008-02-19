VER = speex-svn-14525

CONF_OPTS = \
	--without-ogg \
	--enable-blackfin-asm \
	--enable-fixed-point

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libspeex.so.1 /usr/lib/libspeex.so.1
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libspeexdsp.so.1 /usr/lib/libspeexdsp.so.1
