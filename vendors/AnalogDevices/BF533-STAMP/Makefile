#
#	Makefile -- Build instructions for ADI/Blackfin
#

include $(LINUX_CONFIG)

ROMFSIMG = $(IMAGEDIR)/rootfs
IMAGE    = $(IMAGEDIR)/linux

MKFS_JFFS2  = $(ROOTDIR)/user/mtd-utils/build/mkfs.jffs2
MKFS_YAFFS  = $(ROOTDIR)/user/blkfin-apps/yaffs-utils/utils/mkyaffsimage
MKFS_YAFFS2 = $(ROOTDIR)/user/blkfin-apps/yaffs-utils/utils/mkyaffs2image

# Blocks must be a multiple of 256
BLOCKS   = 8192
INODES   = 1024

ROMFS_DIRS = bin dev etc etc/dhcpc home lib mnt proc sys usr var root home tmp home/httpd home/httpd/cgi-bin etc/boa /etc/config var/run var/lib/misc var/log/boa

all:

romfs:
	mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		mkdir -p $(ROMFSDIR)/$$i; \
	done
	chmod 1777 $(ROMFSDIR)/tmp
	$(ROMFSINST) -s bin /sbin
	$(ROMFSINST) /etc/rc
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
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

BSS      = $$($(CROSS_COMPILE)objdump -h $(IMAGEDIR)/vmlinux | grep .bss | awk '{print "0x"$$4}')
BSS_SIZE = $$($(CROSS_COMPILE)objdump -h $(IMAGEDIR)/vmlinux | grep .bss | awk '{print "0x"$$3}')
ADDR     = $$(echo $$(($(BSS) + $(BSS_SIZE))))

image:
	mkdir -p $(IMAGEDIR)
	rm -rf $(IMAGEDIR)/*
#
# make romfs.[fstype] images, and add them to linux(elf file) if possible
#
	cp $(ROOTDIR)/$(LINUXDIR)/linux $(IMAGEDIR)/vmlinux
	$(CROSS_COMPILE)strip -g $(IMAGEDIR)/vmlinux
	if [ -x $(MKFS_JFFS2) ] && [ -n "$(CONFIG_JFFS_FS)" -o -n "$(CONFIG_JFFS2_FS)" ]; then \
		$(MKFS_JFFS2) -d $(ROMFSDIR) -D device_table.txt -o $(ROMFSIMG).jffs2; \
	fi
	if [ -n "$(CONFIG_YAFFS_FS)" ]; then \
		if [ -x "$(MKFS_YAFFS)" -a -n "$(CONFIG_YAFFS_YAFFS1)" ]; then \
			$(MKFS_YAFFS) $(ROMFSDIR) $(ROMFSIMG).yaffs > /dev/null; \
		fi ; \
		if [ -x "$(MKFS_YAFFS2)" -a -n "$(CONFIG_YAFFS_YAFFS2)" ]; then \
			$(MKFS_YAFFS2) $(ROMFSDIR) $(ROMFSIMG).yaffs2 > /dev/null; \
		fi ; \
	fi
	if [ -n "$(CONFIG_CRAMFS)" ]; then \
		bfin-uclinux-mkcramfs -z -r -D device_table.txt $(ROMFSDIR) $(ROMFSIMG).cramfs ; \
		$(CROSS_COMPILE)objcopy --add-section .romfs=$(ROMFSIMG).cramfs \
		--adjust-section-vma .romfs=$(ADDR) --no-adjust-warnings \
		--set-section-flags .romfs=alloc,load,data $(IMAGEDIR)/vmlinux $(IMAGE).cramfs ;\
	fi
	if [ -n "$(CONFIG_EXT2_FS)" ]; then \
		bfin-uclinux-genext2fs -i $(INODES) -b $(BLOCKS) -d $(ROMFSDIR) -D device_table.txt $(ROMFSIMG).ext2 ; \
		$(CROSS_COMPILE)objcopy --add-section .romfs=$(ROMFSIMG).ext2 \
		--adjust-section-vma .romfs=$(ADDR) --no-adjust-warnings \
		--set-section-flags .romfs=alloc,load,data $(IMAGEDIR)/vmlinux $(IMAGE).ext2 ;\
	fi
	if [ -n "$(CONFIG_ROMFS_FS)" ]; then \
		if  which genromfs >/dev/null 2>&1; then \
			$(ROOTDIR)/tools/mkdevdir.sh $(ROMFSDIR) device_table.txt; \
			genromfs -f $(ROMFSIMG).romfs -d $(ROMFSDIR); \
			$(CROSS_COMPILE)objcopy --add-section .romfs=$(ROMFSIMG).romfs \
			--adjust-section-vma .romfs=$(ADDR) --no-adjust-warnings \
			--set-section-flags .romfs=alloc,load,data $(IMAGEDIR)/vmlinux $(IMAGE).romfs ;\
			rm -rf $(ROMFSDIR)/dev/*; \
		fi; \
	fi
#
# make a compressed image, link the first one to uImage
#
	for FS in cramfs ext2 romfs ; \
	do \
		if [ -f "$(IMAGE).$$FS" ] ; then \
			$(CROSS_COMPILE)objcopy -O binary -S $(IMAGE).$$FS $(IMAGE).bin; \
			gzip -f9 $(IMAGE).bin; \
			$(CROSS_COMPILE)mkimage -A blackfin -O linux -T kernel \
				-C gzip -a $(CONFIG_BOOT_LOAD) -e $(CONFIG_BOOT_LOAD) -n "uClinux Kernel and $$FS" \
				-d $(IMAGE).bin.gz $(IMAGEDIR)/uImage.$$FS; \
			rm $(IMAGE).bin.gz; \
			ln -sf $(IMAGEDIR)/linux.$$FS $(IMAGEDIR)/linux ; \
			ln -sf $(IMAGEDIR)/uImage.$$FS $(IMAGEDIR)/uImage ; \
		fi; \
	done
#
# if we are not attaching a rootfs, make a standalone image
#
	if [ -z "$(CONFIG_MTD_UCLINUX)" ]; then \
		$(CROSS_COMPILE)objcopy -O binary -S $(ROOTDIR)/$(LINUXDIR)/vmlinux \
			$(IMAGEDIR)/vmlinux.bin; \
		gzip -f9 $(IMAGEDIR)/vmlinux.bin; \
		$(CROSS_COMPILE)mkimage -A blackfin -O linux -T kernel \
			-C gzip -a $(CONFIG_BOOT_LOAD) -e $(CONFIG_BOOT_LOAD) -n "uClinux Kernel Only Image" \
			-d $(IMAGEDIR)/vmlinux.bin.gz  $(IMAGEDIR)/vmImage; \
		rm  $(IMAGEDIR)/vmlinux.bin.gz; \
	fi

clean:
