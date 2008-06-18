VER = btsco-0.5

EXTRA_CFLAGS += -g
CONF_OPTS = \
	--enable-alsaplugin \
	LDFLAGS="$(LDFLAGS) -L$(ROOTDIR)/user/blkfin-apps/btsco/build-$(VER)/sbc/" \
	--with-bluez=$(STAGEDIR)/usr \
	--with-alsa-inc-prefix=$(STAGEDIR)/usr/include \
	--with-alsa-prefix=$(STAGEDIR)/usr/lib

include $(ROOTDIR)/tools/autotools.mk

BIN = headsetd a2dpd
romfs:
	set -e ; \
	for b in $(BIN) ; do $(ROMFSINST) -d $(STAGEDIR)/usr/bin/$$b /usr/bin/$$b ; done ;
	cp -d build-$(VER)/alsa-plugins/.libs/libasound_module*.so* $(ROMFSDIR)/usr/lib/
