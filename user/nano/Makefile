VER = nano-2.1.7

CONF_OPTS = \
	--enable-tiny

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/nano /usr/bin/nano
