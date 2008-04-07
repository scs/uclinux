VER = openntpd-3.9p1

CPPFLAGS += -DNTPD_USER=\"ntp\"

CONF_OPTS = \
	--disable-strip

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d build-$(VER)/ntpd /usr/bin/ntpd
	$(ROMFSINST) -d $(VER)/ntpd.conf /etc/ntpd.conf
