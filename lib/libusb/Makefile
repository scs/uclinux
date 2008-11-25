VER = libusb-0.1.12

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libusb-0.1.so.4 /usr/lib/libusb-0.1.so.4
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libusbpp-0.1.so.4 /usr/lib/libusbpp-0.1.so.4
