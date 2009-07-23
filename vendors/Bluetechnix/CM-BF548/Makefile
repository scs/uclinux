#
#	Makefile -- Build instructions for ADI/Blackfin
#

.EXPORT_ALL_VARIABLES:
include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)

# Blocks must be a multiple of 1024
EXT2_BLOCKS = 10240
EXT2_INODES = 1024

ROMFS_DIRS-y = bin etc etc/dhcpc home lib mnt proc sys usr var root home tmp etc/config var/run var/lib/misc
ETC_FILES-y = \
	filesystems group hosts host.conf inetd.conf issue mime.types \
	modprobe.conf motd passwd profile protocols services TZ tux-bf.gif

ROMFS_DIRS-$(CONFIG_USER_BOA_SRC_BOA_NEW) += home/httpd home/httpd/cgi-bin etc/boa var/log/boa
ETC_FILES-$(CONFIG_USER_BOA_SRC_BOA_NEW) += boa.conf index.html tux-wink.gif tuxsit_small.gif

all::

romfs.post:: romfs.shared.libs

romfs::
	mkdir -p $(ROMFSDIR)
	cd $(ROMFSDIR) && mkdir -p $(ROMFS_DIRS-y)
	chmod 1777 $(ROMFSDIR)/tmp
	$(ROMFSINST) -s bin /sbin

	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/mdev.conf
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) -o $(CONFIG_LIB_DIRECTFB_FORCE)$(CONFIG_LIB_DIRECTFB) /etc/directfbrc
	$(ROMFSINST) -e CONFIG_VT -a "tty0:linux:-/bin/sh" /etc/inittab

	set -e ; \
	for f in $(ETC_FILES-y) ; do \
		$(ROMFSINST) ../common/$$f /etc/$$f ; \
	done

	echo "$(VERSIONSTR) -- `date`" > $(ROMFSDIR)/etc/version
ifeq ($(CONFIG_BLACKFIN_INSTALL_UCLINUX_CONFIG),y)
	gzip -9c $(ROOTDIR)/config/.config > $(ROMFSDIR)/root/uclinux-config.gz
endif

ifeq ($(CONFIG_USER_DEV_DYNAMIC),y)
DEVICE_TABLE = device_table-min.txt
else
DEVICE_TABLE = device_table.txt
endif

image::
	mkdir -p $(IMAGEDIR)
	rm -rf $(IMAGEDIR)/*

	$(MAKE) image.rootfs.all
	$(MAKE) image.kernel.all
	$(MAKE) image.uimage.all

clean::

.PHONY: all clean image romfs

include ../../AnalogDevices/vendor.mak
