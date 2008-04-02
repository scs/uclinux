VER = bluez-libs-3.29

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libbluetooth.so.2 /usr/lib/libbluetooth.so.2
