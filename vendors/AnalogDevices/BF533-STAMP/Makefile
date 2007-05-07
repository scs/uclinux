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

ROMFS_DIRS = bin dev etc etc/dhcpc home lib mnt proc sys usr var root home tmp home/httpd home/httpd/cgi-bin etc/boa etc/config var/run var/lib/misc var/log/boa

all:

romfs:
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

BSS      = $$($(CROSS_COMPILE)objdump -h $(IMAGEDIR)/vmlinux | grep .bss | awk '{print "0x"$$4}')
BSS_SIZE = $$($(CROSS_COMPILE)objdump -h $(IMAGEDIR)/vmlinux | grep .bss | awk '{print "0x"$$3}')
ADDR     = $$(echo $$(($(BSS) + $(BSS_SIZE))))

ifeq ($(CONFIG_USER_DEV_DYNAMIC),y)
DEVICE_TABLE = device_table-min.txt
else
DEVICE_TABLE = device_table.txt
endif

image:
	mkdir -p $(IMAGEDIR)
	rm -rf $(IMAGEDIR)/*
#
# make romfs.[fstype] images, and add them to linux(elf file) if possible
#
	cp $(ROOTDIR)/$(LINUXDIR)/linux $(IMAGEDIR)/vmlinux
	$(CROSS_COMPILE)strip -g $(IMAGEDIR)/vmlinux
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
	bfin-uclinux-mkcramfs -z -r -D $(DEVICE_TABLE) $(ROMFSDIR) $(ROMFSIMG).cramfs ; \
		$(CROSS_COMPILE)objcopy --add-section .romfs=$(ROMFSIMG).cramfs \
		--adjust-section-vma .romfs=$(ADDR) --no-adjust-warnings \
		--set-section-flags .romfs=alloc,load,data $(IMAGEDIR)/vmlinux $(IMAGE).cramfs
endif
ifneq ($(CONFIG_EXT2_FS),)
	bfin-uclinux-genext2fs -i $(INODES) -b $(BLOCKS) -d $(ROMFSDIR) -D $(DEVICE_TABLE) $(ROMFSIMG).ext2
	$(CROSS_COMPILE)objcopy --add-section .romfs=$(ROMFSIMG).ext2 \
		--adjust-section-vma .romfs=$(ADDR) --no-adjust-warnings \
		--set-section-flags .romfs=alloc,load,data $(IMAGEDIR)/vmlinux $(IMAGE).ext2
endif
ifneq ($(CONFIG_ROMFS_FS),)
	set -e ; \
	if which genromfs >/dev/null 2>&1; then \
		$(ROOTDIR)/tools/mkdevdir.sh $(ROMFSDIR) $(DEVICE_TABLE); \
		genromfs -f $(ROMFSIMG).romfs -d $(ROMFSDIR); \
		$(CROSS_COMPILE)objcopy --add-section .romfs=$(ROMFSIMG).romfs \
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
			$(CROSS_COMPILE)objcopy -O binary -S $(IMAGE).$$FS $(IMAGE).bin; \
			gzip -f9 $(IMAGE).bin; \
			$(CROSS_COMPILE)mkimage -A blackfin -O linux -T kernel \
				-C gzip -a $(CONFIG_BOOT_LOAD) -e $(CONFIG_BOOT_LOAD) -n "uClinux Kernel and $$FS" \
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
#
# make an initramfs image
#  Note: need to override some vars from userland env
#  Note: we don't compress the cpio initramfs as the u-boot boot images
#        take care of that for us ... no point in double compressing
#
	cd $(ROMFSDIR) && \
	find . | cpio --quiet -H newc -o > $(IMAGEDIR)/rootfs.initramfs
	( awk -f dev-table-to-cpio.awk $(DEVICE_TABLE) ; \
	  echo "slink /init /sbin/init 0755 0 0" ; \
	) | $(ROOTDIR)/$(LINUXDIR)/usr/gen_init_cpio - >> $(IMAGEDIR)/rootfs.initramfs
	cp $(IMAGEDIR)/rootfs.initramfs $(ROOTDIR)/$(LINUXDIR)/usr/initramfs_data.cpio.gz

	CPPFLAGS="" CFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -j$(HOST_NCPU) -C $(ROOTDIR)/$(LINUXDIR)
	cp $(LINUXBOOTDIR)/vmImage $(IMAGEDIR)/uImage.initramfs
	cp $(ROOTDIR)/$(LINUXDIR)/linux $(IMAGEDIR)/linux.initramfs
	ln -sf linux.initramfs $(IMAGEDIR)/linux
	ln -sf uImage.initramfs $(IMAGEDIR)/uImage

endif

clean:

.PHONY: all clean image romfs
