VER = alsa-lib-1.0.12

CONF_OPTS = \
	--with-softfloat \
	--with-versioned=no

# install target is not parallel safe
.NOTPARALLEL:
include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/share/alsa /usr/share/alsa
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libasound.so.2 /usr/lib/libasound.so.2
	$(ROMFSINST) -E CONFIG_SND_MMAP_SUPPORT $(VER)/src/conf/cards/AD1980-no-mmap.conf /usr/share/alsa/cards/AD1980.conf

