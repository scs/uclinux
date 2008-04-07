VER = openntpd-3.9p1

CONF_OPTS = \
	--disable-strip

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d build-$(VER)/ntpd /usr/bin/ntpd
