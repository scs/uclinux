VER = libmodbus-2.0.3
URL = http://launchpad.net/libmodbus/trunk/$(patsubst libmodbus-%,%,$(VER))/+download/$(VER).tar.gz

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libmodbus.so.2 /usr/lib/libmodbus.so.2
