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
	modprobe.conf motd passwd protocols services TZ tux-bf.gif

ROMFS_DIRS-$(CONFIG_USER_BOA_SRC_BOA) += home/httpd home/httpd/cgi-bin etc/boa var/log/boa
ETC_FILES-$(CONFIG_USER_BOA_SRC_BOA) += boa.conf index.html tux-wink.gif tuxsit_small.gif

all:

romfs:
	mkdir -p $(ROMFSDIR)
	cd $(ROMFSDIR) && mkdir -p $(ROMFS_DIRS-y)
	chmod 1777 $(ROMFSDIR)/tmp
	$(ROMFSINST) -s bin /sbin

	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/inittab

	set -e ; \
	for f in $(ETC_FILES-y) ; do \
		$(ROMFSINST) ../common/$$f /etc/$$f ; \
	done

	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

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
	rm -rf $(ROMFSDIR)/dev;
#
# make romfs.[fstype] images, and add them to linux(elf file) if possible
#
	cp $(ROOTDIR)/$(LINUXDIR)/linux $(IMAGEDIR)/vmlinux
	$(CROSS_COMPILE)strip -g $(IMAGEDIR)/vmlinux
	if [ -x $(MKFS_JFFS2) ] && [ -n "$(CONFIG_JFFS_FS)" -o -n "$(CONFIG_JFFS2_FS)" ]; then \
		$(MKFS_JFFS2) -l -d $(ROMFSDIR) -D $(DEVICE_TABLE) -o $(ROMFSIMG).jffs2; \
	fi
	set -e ; \
	if [ -n "$(CONFIG_YAFFS_FS)" ]; then \
		if [ -x "$(MKFS_YAFFS)" -a -n "$(CONFIG_YAFFS_YAFFS1)" ]; then \
			$(MKFS_YAFFS) $(ROMFSDIR) $(ROMFSIMG).yaffs > /dev/null ; \
		fi ; \
		if [ -x "$(MKFS_YAFFS2)" -a -n "$(CONFIG_YAFFS_YAFFS2)" ]; then \
			$(MKFS_YAFFS2) $(ROMFSDIR) $(ROMFSIMG).yaffs2 > /dev/null ; \
		fi ; \
	fi ; \
	if [ -n "$(CONFIG_CRAMFS)" ]; then \
		bfin-uclinux-mkcramfs -z -r -D $(DEVICE_TABLE) $(ROMFSDIR) $(ROMFSIMG).cramfs ; \
		$(CROSS_COMPILE)objcopy --add-section .romfs=$(ROMFSIMG).cramfs \
		--adjust-section-vma .romfs=$(ADDR) --no-adjust-warnings \
		--set-section-flags .romfs=alloc,load,data $(IMAGEDIR)/vmlinux $(IMAGE).cramfs ; \
	fi ; \
	if [ -n "$(CONFIG_EXT2_FS)" ]; then \
		bfin-uclinux-genext2fs -i $(INODES) -b $(BLOCKS) -d $(ROMFSDIR) -D $(DEVICE_TABLE) $(ROMFSIMG).ext2 ; \
		$(CROSS_COMPILE)objcopy --add-section .romfs=$(ROMFSIMG).ext2 \
		--adjust-section-vma .romfs=$(ADDR) --no-adjust-warnings \
		--set-section-flags .romfs=alloc,load,data $(IMAGEDIR)/vmlinux $(IMAGE).ext2 ; \
	fi ; \
	if [ -n "$(CONFIG_ROMFS_FS)" ]; then \
		if  which genromfs >/dev/null 2>&1; then \
			$(ROOTDIR)/tools/mkdevdir.sh $(ROMFSDIR) $(DEVICE_TABLE); \
			genromfs -f $(ROMFSIMG).romfs -d $(ROMFSDIR); \
			$(CROSS_COMPILE)objcopy --add-section .romfs=$(ROMFSIMG).romfs \
			--adjust-section-vma .romfs=$(ADDR) --no-adjust-warnings \
			--set-section-flags .romfs=alloc,load,data $(IMAGEDIR)/vmlinux $(IMAGE).romfs ; \
			rm -rf $(ROMFSDIR)/dev/*; \
		fi; \
	fi
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
#
# grab the standalone kernel image
#
	cp $(LINUXBOOTDIR)/vmImage $(IMAGEDIR)/vmImage

clean:
