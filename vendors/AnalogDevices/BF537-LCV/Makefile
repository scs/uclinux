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
BLOCKS   = 16384
INODES   = 1024

ROMFS_DIRS = bin etc etc/dhcpc home lib mnt proc sys usr var root home tmp home/httpd home/httpd/cgi-bin etc/boa etc/config var/run var/lib/misc var/log/boa

all::

romfs.post:: romfs.shared.libs

romfs::
	mkdir -p $(ROMFSDIR)
	cd $(ROMFSDIR) && mkdir -p $(ROMFS_DIRS)
	chmod 1777 $(ROMFSDIR)/tmp
	$(ROMFSINST) -s bin /sbin
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/mdev.conf
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) /etc/services
	$(ROMFSINST) /etc/protocols
	$(ROMFSINST) /etc/passwd
	$(ROMFSINST) /etc/group
	$(ROMFSINST) /etc/motd
	$(ROMFSINST) /etc/issue
	$(ROMFSINST) /etc/TZ
	$(ROMFSINST) /etc/hosts
	$(ROMFSINST) /etc/host.conf
	$(ROMFSINST) /etc/boa.conf
	$(ROMFSINST) /etc/mime.types
	$(ROMFSINST) /etc/inetd.conf
	$(ROMFSINST) /etc/index.html
	$(ROMFSINST) /etc/tux-wink.gif
	$(ROMFSINST) /etc/tuxsit_small.gif
	$(ROMFSINST) /etc/modprobe.conf
	echo "$(VERSIONSTR) -- `date`" > $(ROMFSDIR)/etc/version

BSS      = $$($(CROSS_COMPILE)objdump -h $(IMAGEDIR)/vmlinux | awk '/.bss/ {print "0x"$$4}')
BSS_SIZE = $$($(CROSS_COMPILE)objdump -h $(IMAGEDIR)/vmlinux | awk '/.bss/ {print "0x"$$3}')
ADDR     = $$(echo $$(($(BSS) + $(BSS_SIZE))))
ENTRY    = $$($(CROSS_COMPILE)nm $(IMAGE).$$FS | awk '$$NF == "__start" {print $$1}')

ifeq ($(CONFIG_USER_DEV_DYNAMIC),y)
DEVICE_TABLE = device_table-min.txt
else
DEVICE_TABLE = device_table.txt
endif

image::
	mkdir -p $(IMAGEDIR)
	rm -rf $(IMAGEDIR)/*
	rm -rf $(ROMFSDIR)/dev;
#
# make romfs.[fstype] images, and add them to linux(elf file) if possible
#
	cp $(ROOTDIR)/$(LINUXDIR)/linux $(IMAGEDIR)/vmlinux
	$(STRIP) -g $(IMAGEDIR)/vmlinux
	set -e ; \
	if [ -x $(MKFS_JFFS2) ] && [ -n "$(CONFIG_JFFS_FS)" -o -n "$(CONFIG_JFFS2_FS)" ]; then \
		$(MKFS_JFFS2) -d $(ROMFSDIR) -D $(DEVICE_TABLE) -o $(ROMFSIMG).jffs2; \
	fi
ifneq ($(CONFIG_YAFFS_FS),)
	set -e ; \
	if [ -x "$(MKFS_YAFFS)" -a -n "$(CONFIG_YAFFS_YAFFS1)" ]; then \
		$(MKFS_YAFFS) $(ROMFSDIR) $(ROMFSIMG).yaffs > /dev/null ; \
	fi ; \
	if [ -x "$(MKFS_YAFFS2)" -a -n "$(CONFIG_YAFFS_YAFFS2)" ]; then \
		$(MKFS_YAFFS2) $(ROMFSDIR) $(ROMFSIMG).yaffs2 > /dev/null ; \
	fi
endif
ifneq ($(CONFIG_CRAMFS),)
	$(CROSS_COMPILE)mkcramfs -z -r -D $(DEVICE_TABLE) $(ROMFSDIR) $(ROMFSIMG).cramfs
	$(OBJCOPY) --add-section .romfs=$(ROMFSIMG).cramfs \
		--adjust-section-vma .romfs=$(ADDR) --no-adjust-warnings \
		--set-section-flags .romfs=alloc,load,data $(IMAGEDIR)/vmlinux $(IMAGE).cramfs
endif
ifneq ($(CONFIG_EXT2_FS),)
	$(CROSS_COMPILE)genext2fs -m 0 -i $(INODES) -b $(BLOCKS) -d $(ROMFSDIR) -D $(DEVICE_TABLE) $(ROMFSIMG).ext2
	$(OBJCOPY) --add-section .romfs=$(ROMFSIMG).ext2 \
		--adjust-section-vma .romfs=$(ADDR) --no-adjust-warnings \
		--set-section-flags .romfs=alloc,load,data $(IMAGEDIR)/vmlinux $(IMAGE).ext2
endif
ifneq ($(CONFIG_ROMFS_FS),)
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

	cp $(IMAGEDIR)/linux /tftpboot
	cp $(IMAGEDIR)/uImage /tftpboot


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

	cp $(IMAGEDIR)/linux /tftpboot
	cp $(IMAGEDIR)/uImage /tftpboot

endif
endif

clean::

.PHONY: all clean image romfs

include ../vendor.mak
