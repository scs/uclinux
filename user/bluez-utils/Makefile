VER = bluez-utils-2.25

CONF_OPTS-y =
CONF_SBIN-y =
CONF_OPTS-$(CONFIG_LIB_LIBUSB) += --enable-bccmd
CONF_SBIN-$(CONFIG_LIB_LIBUSB) += bccmd

CONF_OPTS = \
	--with-bluez=$(STAGEDIR) \
	--without-openobex \
	--without-dbus \
	--without-fuse \
	--enable-test-programs \
	--with-alsa=$(STAGEDIR) \
	--with-usb=$(STAGEDIR) \
	$(CONF_OPTS-y)

include $(ROOTDIR)/tools/autotools.mk

BIN = bluepin ciptool dund hcitool hidd l2ping pand rfcomm sdptool
SBIN = hciattach hciconfig hcid sdpd $(CONF_SBIN-y)
ETC = hcid.conf pin rfcomm.conf
romfs:
	set -e ; \
	for b in $(BIN) ; do $(ROMFSINST) -d $(STAGEDIR)/usr/bin/$$b /usr/bin/$$b ; done ; \
	for b in $(SBIN) ; do $(ROMFSINST) -d $(STAGEDIR)/usr/sbin/$$b /usr/sbin/$$b ; done ; \
	for b in $(ETC) ; do $(ROMFSINST) -d $(STAGEDIR)/etc/bluetooth/$$b /etc/bluetooth/$$b ; done
