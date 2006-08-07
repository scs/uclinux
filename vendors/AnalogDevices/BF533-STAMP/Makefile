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
	[ -d $(ROMFSDIR) ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
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

image:
	if [ -d $(IMAGEDIR) ] ; then \
		mkdir -p $(IMAGEDIR) ;\
	fi
#
# make romfs.[fstype] images, and add them to linux(elf file) if possible
#
	cp $(ROOTDIR)/$(LINUXDIR)/linux $(IMAGEDIR)
	$(CROSS_COMPILE)strip -g $(IMAGEDIR)/linux
	if [ -x $(MKFS_JFFS2) ] && [ -n "$(CONFIG_JFFS_FS)" -o -n "$(CONFIG_JFFS2_FS)" ]; then \
		$(MKFS_JFFS2) -d $(ROMFSDIR) -D device_table.txt -o $(ROMFSIMG).jffs2; \
	fi
	if [ -n "$(CONFIG_YAFFS_FS)" ]; then \
		if [ -x "$(MKFS_YAFFS)" -a -n "$(CONFIG_YAFFS_YAFFS1)" ]; then \
			$(MKFS_YAFFS) $(ROMFSDIR) $(ROMFSIMG).yaffs; \
		fi ; \
		if [ -x "$(MKFS_YAFFS2)" -a -n "$(CONFIG_YAFFS_YAFFS2)" ]; then \
			$(MKFS_YAFFS2) $(ROMFSDIR) $(ROMFSIMG).yaffs2; \
		fi ; \
	fi
	if [ -n "$(CONFIG_CRAMFS)" ]; then \
		bfin-uclinux-mkcramfs -z -r -D device_table.txt $(ROMFSDIR) $(ROMFSIMG).cramfs ; \
		BSS=`set -- \`$(CROSS_COMPILE)objdump -h $(IMAGEDIR)/linux | grep .bss\` ; echo 0x$${4}` ; \
		BSS_SIZE=`set -- \`$(CROSS_COMPILE)objdump -h $(IMAGEDIR)/linux | grep .bss\` ; echo 0x$${3}` ; \
		ADDR=$$(($$BSS + $$BSS_SIZE)) ; \
		$(CROSS_COMPILE)objcopy --add-section .romfs=$(ROMFSIMG).cramfs \
		--adjust-section-vma .romfs=$${ADDR} --no-adjust-warnings \
		--set-section-flags .romfs=alloc,load,data $(IMAGEDIR)/linux $(IMAGE).cramfs ;\
	fi
	if [ -n "$(CONFIG_EXT2_FS)" ]; then \
		bfin-uclinux-genext2fs -i $(INODES) -b $(BLOCKS) -d $(ROMFSDIR) -D device_table.txt $(ROMFSIMG).ext2 ; \
		BSS=`set -- \`$(CROSS_COMPILE)objdump -h $(IMAGEDIR)/linux | grep .bss\` ; echo 0x$${4}` ; \
		BSS_SIZE=`set -- \`$(CROSS_COMPILE)objdump -h $(IMAGEDIR)/linux | grep .bss\` ; echo 0x$${3}` ; \
		ADDR=$$(($$BSS + $$BSS_SIZE)) ; \
		$(CROSS_COMPILE)objcopy --add-section .romfs=$(ROMFSIMG).ext2 \
		--adjust-section-vma .romfs=$${ADDR} --no-adjust-warnings \
		--set-section-flags .romfs=alloc,load,data $(IMAGEDIR)/linux $(IMAGE).ext2 ;\
	fi
#
# make a compressed image, link the first one to uImage
#
	for FS in cramfs ext2 ; \
	do \
		if [ -f "$(IMAGE).$$FS" ] ; then \
			$(CROSS_COMPILE)objcopy -O binary -S $(IMAGE).$$FS $(IMAGE).bin; \
			gzip -f9 $(IMAGE).bin; \
			$(CROSS_COMPILE)mkimage -A blackfin -O linux -T kernel \
				-C gzip -a $(CONFIG_BOOT_LOAD) -e $(CONFIG_BOOT_LOAD) -n "uClinux Kernel and $$FS" \
				-d $(IMAGE).bin.gz $(IMAGEDIR)/uImage.$$FS; \
			rm $(IMAGE).bin.gz; \
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
	fi ; \

clean:
