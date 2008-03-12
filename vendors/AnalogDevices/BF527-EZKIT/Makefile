#
#	Makefile -- Build instructions for ADI/Blackfin
#

.EXPORT_ALL_VARIABLES:
include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)

ROMFSIMG = $(IMAGEDIR)/rootfs
IMAGE    = $(IMAGEDIR)/linux

MKFS_JFFS2  = $(ROOTDIR)/user/mtd-utils/build/mkfs.jffs2
MKFS_YAFFS  = $(ROOTDIR)/user/blkfin-apps/yaffs-utils/utils/mkyaffsimage
MKFS_YAFFS2 = $(ROOTDIR)/user/blkfin-apps/yaffs-utils/utils/mkyaffs2image

LINUXBOOTDIR = $(ROOTDIR)/$(LINUXDIR)/arch/$(ARCH)/boot

# Blocks must be a multiple of 1024
BLOCKS   = 8192
INODES   = 1024

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
	$(ROMFSINST) -o $(CONFIG_LIB_DIRECTFB_FORCE)$(CONFIG_LIB_DIRECTFB) /etc/directfbrc

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

ADDR     = $$($(CROSS_COMPILE)readelf -s $(IMAGEDIR)/vmlinux | awk '$$NF == "__end" {print "0x"$$2}')
ENTRY    = $$($(CROSS_COMPILE)nm $(IMAGE).$$FS | awk '$$NF == "__start" {print $$1}')

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

image::
	mkdir -p $(IMAGEDIR)
	rm -rf $(IMAGEDIR)/*
#
# make romfs.[fstype] images, and add them to linux(elf file) if possible
#
	cp $(ROOTDIR)/$(LINUXDIR)/linux $(IMAGEDIR)/vmlinux
	$(STRIP) -g $(IMAGEDIR)/vmlinux
	set -e ; \
	if [ -x $(MKFS_JFFS2) ] && [ -n "$(CONFIG_JFFS_FS)" -o -n "$(CONFIG_JFFS2_FS)" ]; then \
		$(MKFS_JFFS2) -l -d $(ROMFSDIR) -D $(DEVICE_TABLE) -o $(ROMFSIMG).jffs2; \
	fi
ifeq ($(CONFIG_YAFFS_FS),y)
	set -e ; \
	if [ -x "$(MKFS_YAFFS)" -a -n "$(CONFIG_YAFFS_YAFFS1)" ]; then \
		$(MKFS_YAFFS) $(ROMFSDIR) $(ROMFSIMG).yaffs > /dev/null ; \
	fi ; \
	if [ -x "$(MKFS_YAFFS2)" -a -n "$(CONFIG_YAFFS_YAFFS2)" ]; then \
		$(MKFS_YAFFS2) $(ROMFSDIR) $(ROMFSIMG).yaffs2 > /dev/null ; \
	fi
endif
ifeq ($(CONFIG_CRAMFS),y)
	$(CROSS_COMPILE)mkcramfs -z -D $(DEVICE_TABLE) $(ROMFSDIR) $(ROMFSIMG).cramfs
	$(OBJCOPY) --add-section .romfs=$(ROMFSIMG).cramfs \
		--adjust-section-vma .romfs=$(ADDR) --no-adjust-warnings \
		--set-section-flags .romfs=alloc,load,data $(IMAGEDIR)/vmlinux $(IMAGE).cramfs
endif
ifeq ($(CONFIG_EXT2_FS),y)
	$(CROSS_COMPILE)genext2fs -m 0 -i $(INODES) -b $(BLOCKS) -d $(ROMFSDIR) -D $(DEVICE_TABLE) $(ROMFSIMG).ext2
	$(OBJCOPY) --add-section .romfs=$(ROMFSIMG).ext2 \
		--adjust-section-vma .romfs=$(ADDR) --no-adjust-warnings \
		--set-section-flags .romfs=alloc,load,data $(IMAGEDIR)/vmlinux $(IMAGE).ext2
endif
ifeq ($(CONFIG_ROMFS_FS),y)
	set -e ; \
	if which genromfs >/dev/null 2>&1; then \
		$(ROOTDIR)/tools/mkdevdir.sh $(ROMFSDIR) $(DEVICE_TABLE); \
		genromfs -f $(ROMFSIMG).romfs -d $(ROMFSDIR); \
		$(OBJCOPY) --add-section .romfs=$(ROMFSIMG).romfs \
			--adjust-section-vma .romfs=$(ADDR) --no-adjust-warnings \
			--set-section-flags .romfs=alloc,load,data $(IMAGEDIR)/vmlinux $(IMAGE).romfs ; \
		rm -rf $(ROMFSDIR)/dev/*; \
	fi
endif

ifeq ($(CONFIG_MTD_UCLINUX),y)

#
# make a compressed image, link the first one to uImage
#
	set -e ; \
	for FS in cramfs ext2 romfs ; \
	do \
		if [ -f "$(IMAGE).$$FS" ] ; then \
			$(OBJCOPY) -O binary -S $(IMAGE).$$FS $(IMAGE).bin; \
			gzip -f9 $(IMAGE).bin; \
			$(CROSS_COMPILE)mkimage -A blackfin -O linux -T kernel \
				-C gzip -a $(CONFIG_BOOT_LOAD) -e $(ENTRY) -n "uClinux Kernel and $$FS" \
				-d $(IMAGE).bin.gz $(IMAGEDIR)/uImage.$$FS; \
			rm $(IMAGE).bin.gz; \
			ln -sf linux.$$FS $(IMAGEDIR)/linux ; \
			ln -sf uImage.$$FS $(IMAGEDIR)/uImage ; \
		fi; \
	done
	rm -f $(IMAGEDIR)/vmlinux
	rm -f $(IMAGEDIR)/vmImage

else

	cp $(LINUXBOOTDIR)/vmImage $(IMAGEDIR)/vmImage

ifeq ($(CONFIG_BLK_DEV_INITRD),y)

#
# make an initramfs image
#  Note: need to override some vars from userland env
#

	/bin/bash $(ROOTDIR)/$(LINUXDIR)/scripts/gen_initramfs_list.sh -u squash -g squash $(ROMFSDIR) > $(IMAGEDIR)/rootfs.initramfs.contents
	awk -f dev-table-to-cpio.awk $(DEVICE_TABLE) >> $(IMAGEDIR)/rootfs.initramfs.contents
	echo "slink /init /sbin/init 0755 0 0" >> $(IMAGEDIR)/rootfs.initramfs.contents
	$(ROOTDIR)/$(LINUXDIR)/usr/gen_init_cpio $(IMAGEDIR)/rootfs.initramfs.contents > $(IMAGEDIR)/rootfs.initramfs
	gzip -c -9 $(IMAGEDIR)/rootfs.initramfs > $(IMAGEDIR)/rootfs.initramfs.gz

# first one set with the rootfs compressed (to work with uncompressed kernel)
	cp $(IMAGEDIR)/rootfs.initramfs.gz $(ROOTDIR)/$(LINUXDIR)/usr/initramfs_data.cpio.gz
	CPPFLAGS="" CFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -j$(HOST_NCPU) -C $(ROOTDIR)/$(LINUXDIR)
	cp $(LINUXBOOTDIR)/vmImage $(IMAGEDIR)/uImage.initramfs.gz
	cp $(ROOTDIR)/$(LINUXDIR)/System.map $(IMAGEDIR)/System.map.initramfs.gz
	cp $(ROOTDIR)/$(LINUXDIR)/vmlinux $(IMAGEDIR)/linux.initramfs.gz
	ln -sf linux.initramfs.gz $(IMAGEDIR)/linux

# then one set with the rootfs uncompressed (since u-boot images do compression)
# we want to do this step last since it will leave the kernel dir in a state
# that properly reflects the default uImage
	cp $(IMAGEDIR)/rootfs.initramfs $(ROOTDIR)/$(LINUXDIR)/usr/initramfs_data.cpio.gz
	CPPFLAGS="" CFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -j$(HOST_NCPU) -C $(ROOTDIR)/$(LINUXDIR)
	cp $(LINUXBOOTDIR)/vmImage $(IMAGEDIR)/uImage.initramfs
	cp $(ROOTDIR)/$(LINUXDIR)/System.map $(IMAGEDIR)/System.map.initramfs
	cp $(ROOTDIR)/$(LINUXDIR)/vmlinux $(IMAGEDIR)/linux.initramfs
	ln -sf uImage.initramfs $(IMAGEDIR)/uImage

endif
endif

clean::

.PHONY: all clean image romfs

include ../vendor.mak
