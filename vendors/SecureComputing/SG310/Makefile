#
#	Makefile -- Build instructions for SecureComputing/SG310
#

ROMFSIMG      = $(IMAGEDIR)/ramdisk
ZIMAGE        = $(IMAGEDIR)/zImage
IMAGE         = $(IMAGEDIR)/image.bin
IMAGESIZE     = 7471104
SQUASH_ENDIAN = -le

ROMFS_DIRS    = $(DEFAULT_ROMFS_DIRS)

DEVICES      += $(DEVICE_PTY_64)

FLASH_DEVICES ?= \
        boot,c,90,0 \
        config,c,90,2 \
        image,c,90,4 \
        all,c,90,6 \
        tags,c,90,8 \
        log,c,90,10


all:

clean: image.clean

romfs: romfs_dev romfs.dirs romfs.symlinks romfs.default romfs.rc romfs.version romfs.boot romfs.cryptokey
	$(ROMFSINST) ../network.init.std /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init

image: image.configs image.dir image.arm.zimage image.squashfs7z image.bin image.size image.tag image.copy

include $(ROOTDIR)/vendors/config/config.dev
include ../vendor.mak
