VER = mpc-0.12.1

CONF_OPTS = \
	--disable-iconv

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/mpc /usr/bin/mpc
