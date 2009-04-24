#
#	Makefile -- Build instructions for ADI/Blackfin
#

.EXPORT_ALL_VARIABLES:
include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)

# Blocks must be a multiple of 1024
EXT2_BLOCKS = 16384

ROMFS_DIRS-y = bin etc etc/dhcpc home lib mnt proc sys usr var root home tmp etc/config var/run var/lib/misc
ETC_FILES-y = \
	filesystems group issue mdev.conf mime.types modprobe.conf motd \
	passwd profile rc TZ tux-bf.gif
WEB_FILES-y =

ETC_FILES-$(CONFIG_NET) += hosts host.conf protocols services
ETC_FILES-$(CONFIG_USER_INETD_INETD) += inetd.conf
ETC_FILES-$(CONFIG_USER_BUSYBOX_INETD) += inetd.conf

ROMFS_DIRS-$(CONFIG_USER_BOA_SRC_BOA) += home/httpd home/httpd/cgi-bin etc/boa var/log/boa
ETC_FILES-$(CONFIG_USER_BOA_SRC_BOA) += boa.conf
WEB_FILES-$(CONFIG_USER_BOA_SRC_BOA) += boa.conf index.html tux-bf.gif tux-wink.gif tuxsit_small.gif favicon.ico

all::

romfs.post:: romfs.shared.libs

romfs::
	mkdir -p $(ROMFSDIR)
	cd $(ROMFSDIR) && mkdir -p $(ROMFS_DIRS-y)
	chmod 1777 $(ROMFSDIR)/tmp
	$(ROMFSINST) -s bin /sbin

	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) -o $(CONFIG_LIB_DIRECTFB_FORCE)$(CONFIG_LIB_DIRECTFB) /etc/directfbrc
	$(ROMFSINST) -e CONFIG_VT -E CONFIG_USER_LOGIN_LOGIN -E CONFIG_USER_BUSYBOX_LOGIN \
		-a "tty0:linux:-/bin/sh" /etc/inittab
	$(ROMFSINST) -e CONFIG_VT -o $(CONFIG_USER_LOGIN_LOGIN)$(CONFIG_USER_BUSYBOX_LOGIN) \
		-a "tty0:linux:/bin/login -f root" /etc/inittab
	$(ROMFSINST) -E CONFIG_USER_INIT_CONSOLE_SH -E CONFIG_USER_LOGIN_LOGIN -E CONFIG_USER_BUSYBOX_LOGIN \
		-a "ttyBF0:vt110:-bin/sh" /etc/inittab
	$(ROMFSINST) -E CONFIG_USER_INIT_CONSOLE_SH -o $(CONFIG_USER_LOGIN_LOGIN)$(CONFIG_USER_BUSYBOX_LOGIN) \
		-a "ttyBF0:vt110:/bin/login -f root" /etc/inittab
	$(ROMFSINST) -E CONFIG_USER_BUSYBOX_LOGIN -a "cat /etc/motd" /etc/rc


	set -e ; \
	for f in $(ETC_FILES-y) ; do \
		$(ROMFSINST) ../common/$$f /etc/$$f ; \
	done ; \
	for f in $(WEB_FILES-y) ; do \
		$(ROMFSINST) ../common/$$f /home/httpd/$$f ; \
	done

	echo "$(VERSIONSTR) -- `date`" > $(ROMFSDIR)/etc/version
ifeq ($(CONFIG_BLACKFIN_INSTALL_UCLINUX_CONFIG),y)
	gzip -9c $(ROOTDIR)/config/.config > $(ROMFSDIR)/root/uclinux-config.gz
	gzip -9c $(ROOTDIR)/.config > $(ROMFSDIR)/root/vendor-board-config.gz
endif

ifeq ($(CONFIG_USER_DEV_DYNAMIC),y)
DEVICE_TABLE = device_table-min.txt
else
ifeq ($(CONFIG_USER_BUSYBOX_MDEV),y)
$(warning )
$(warning You have busybox's mdev enabled.  The static device tree will be)
$(warning overridden during boot by a tmpfs in /dev.)
$(warning )
endif
DEVICE_TABLE = device_table.txt
endif

# these targets can be found in AnalogDevices/vendor.mak
image::
	mkdir -p $(IMAGEDIR)
	rm -rf $(IMAGEDIR)/*

	$(MAKE) image.rootfs.all
	$(MAKE) image.kernel.all
	$(MAKE) image.uimage.all

clean::

.PHONY: all clean image romfs

include ../../AnalogDevices/vendor.mak
