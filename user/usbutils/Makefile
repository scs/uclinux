VER = usbutils-0.81
URL = http://downloads.sourceforge.net/sourceforge/linux-usb/$(VER).tar.bz2

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/sbin/lsusb /usr/bin/lsusb
	$(ROMFSINST) -d $(STAGEDIR)/usr/share/usb.ids /usr/share/usb.ids
