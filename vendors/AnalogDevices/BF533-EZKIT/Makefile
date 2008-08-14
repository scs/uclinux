#
#	Makefile -- Build instructions for ADI/Blackfin
#

.EXPORT_ALL_VARIABLES:
include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)

# Blocks must be a multiple of 1024
EXT2_BLOCKS = 8192
EXT2_INODES = 1024

ROMFS_DIRS-y = bin etc etc/dhcpc home lib mnt proc sys usr var root home tmp etc/config var/run var/lib/misc
ETC_FILES-y = \
	filesystems group hosts host.conf inetd.conf issue mime.types \
	modprobe.conf motd passwd protocols services TZ tux-bf.gif \
	rc mdev.conf
WEB_FILES-y =

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

include ../vendor.mak
