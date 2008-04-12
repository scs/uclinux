VER = nano-2.1.1

CONF_OPTS = \
	--disable-tiny

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/nano /usr/bin/nano
