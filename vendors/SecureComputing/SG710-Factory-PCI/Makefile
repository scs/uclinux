#
#	Makefile -- Build instructions for CyberGuard SG710-Factory-PCI
#

ROMFSIMG  = $(IMAGEDIR)/ramdisk
ZIMAGE    = $(IMAGEDIR)/zImage
IMAGE     = $(IMAGEDIR)/D$(VERSIONNAME).bin
MBRIMG    = $(IMAGEDIR)/mbr.img

SQUASH_ENDIAN = -be

ROMFS_DIRS = $(DEFAULT_ROMFS_DIRS)

FLASH_DEVICES = \
	boot,c,90,0 \
	bootarg,c,90,0 \
	ethmac,c,90,0 \
	image,b,93,0 \
	config,b,93,2 \
	all,b,93,0

all:

clean: image.clean

romfs: romfs_dev romfs.dirs romfs.symlinks romfs.recover romfs.rc romfs.version
	$(ROMFSINST) /etc/network.init

romfs.post:: romfs.no-ixp400-modules romfs.ixp425-microcode

#image: image.configs image.dir image.arm.zimage image.squashfs7z image.bin image.tag image.copy
image: image.configs image.dir image.arm.zimage image.squashfs7z image.mbr image.bin image.tag image.copy

.PHONY: image.mbr

image.mbr: $(MBRIMG)

$(MBRIMG):
	$(DD) if=/dev/zero of=$@ bs=512 count=1
	echo -e "1,48575,L,*\n,,61,-" | /sbin/sfdisk  -uS -C 966 -H 16 -S 4 $@

include $(ROOTDIR)/vendors/config/config.dev
include ../vendor.mak
