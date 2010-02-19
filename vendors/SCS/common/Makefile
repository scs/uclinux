#
#	Makefile -- Build instructions for ADI/Blackfin
#

.EXPORT_ALL_VARIABLES:
include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)

ROMFS_DIRS = bin etc etc/boa etc/dhcpc home lib mnt proc sys usr var root home tmp var/run var/lib/misc home/httpd home/httpd/cgi-bin var/log/boa

ETC_FILES = TZ boa.conf filesystems fstab fw_env.config group host.conf hosts inetd.conf inittab issue mdev.conf motd mime.types modprobe.conf passwd profile protocols rc services hotplug_sd
BIN_FILES = maintenance netviewd fw_printenv fw_setenv tftp-get

# Blocks must be a multiple of 1024
BLOCKS   = 8192
INODES   = 1024


all::

romfs.post:: romfs.shared.libs

romfs::
	rm -rf $(ROMFSDIR)
	mkdir -p $(ROMFSDIR)
	cd $(ROMFSDIR) && mkdir -p $(ROMFS_DIRS)
	chmod 1777 $(ROMFSDIR)/tmp
	$(ROMFSINST) -s bin /sbin


	set -e;\
	for f in $(ETC_FILES) ; do \
		$(ROMFSINST) $$f /etc/$$f || $(ROMFSINST) ../common/$$f /etc/$$f ; \
	done
	set -e;\
	for i in $(BIN_FILES); do\
		$(ROMFSINST) -P $$i /bin/$$i || $(ROMFSINST) -P ../common/$$i /bin/$$i || { make -C ../apps $$i && $(ROMFSINST) -P ../apps/$$i /bin/$$i; };\
	done

	echo "$(VERSIONSTR) -- `date`" > $(ROMFSDIR)/etc/version
ifeq ($(CONFIG_BLACKFIN_INSTALL_UCLINUX_CONFIG),y)
	gzip -9c $(ROOTDIR)/config/.config > $(ROMFSDIR)/etc/uclinux-config.gz
	gzip -9c $(ROOTDIR)/.config > $(ROMFSDIR)/etc/vendor-board-config.gz
endif

ifeq ($(CONFIG_USER_DEV_DYNAMIC),y)
DEVICE_TABLE = ../common/device_table-min.txt
else
DEVICE_TABLE = ../common/device_table.txt
endif

image::
	mkdir -p $(IMAGEDIR)
	rm -rf $(IMAGEDIR)/*

	$(MAKE) image.rootfs.all
	$(MAKE) image.kernel.all
	$(MAKE) image.uimage.all

clean::

.PHONY: all clean image romfs

	#$(MAKE) -C ../apps clean

include ../vendor.mak
