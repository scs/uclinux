#
#	Makefile -- Build instructions for the BF533-STAMP from Analog Devices
#
include $(LINUX_CONFIG)

ROMFSIMG = $(IMAGEDIR)/rootfs.img
JFFS2IMG = $(IMAGEDIR)/jffs2.img
IMAGE    = $(IMAGEDIR)/linux

MKFS_JFFS2 = $(ROOTDIR)/user/mtd-utils/build/mkfs.jffs2

# Blocks must be a multiple of 256
BLOCKS   = 8192
INODES   = 1024

ROMFS_DIRS = bin dev etc etc/dhcpc home lib mnt proc sys usr var root home tmp home/httpd home/httpd/cgi-bin etc/boa /etc/config var/run var/lib/misc var/log/boa

romfs:
	[ -d $(ROMFSDIR) ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	chmod 777 $(ROMFSDIR)/tmp
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
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	if [ -x $(MKFS_JFFS2) ]; then \
		$(MKFS_JFFS2) -d $(ROMFSDIR) -D device_table.txt -o $(JFFS2IMG); \
	fi
	bfin-elf-genext2fs -i $(INODES) -b $(BLOCKS) -d $(ROMFSDIR) -D device_table.txt $(ROMFSIMG)
	cp $(ROOTDIR)/$(LINUXDIR)/linux $(IMAGEDIR)
	$(CROSS_COMPILE)strip -g $(IMAGEDIR)/linux
	BSS=`set -- \`$(CROSS_COMPILE)objdump -h $(IMAGEDIR)/linux | grep .bss\` ; echo 0x$${4}` ; \
	BSS_SIZE=`set -- \`$(CROSS_COMPILE)objdump -h $(IMAGEDIR)/linux | grep .bss\` ; echo 0x$${3}` ; \
	ADDR=$$(($$BSS + $$BSS_SIZE)) ; \
	$(CROSS_COMPILE)objcopy --add-section .romfs=$(IMAGEDIR)/rootfs.img \
	--adjust-section-vma .romfs=$${ADDR} --no-adjust-warnings \
	--set-section-flags .romfs=alloc,load,data \
	$(IMAGEDIR)/linux concat.dxe
	mv concat.dxe $(IMAGE)

#
# make a compressed image
#
	if [ -f  $(IMAGE) ] ; then \
		$(CROSS_COMPILE)objcopy -O binary -S $(IMAGE) $(IMAGE).bin; \
		gzip -f9 $(IMAGE).bin; \
		$(CROSS_COMPILE)mkimage -A blackfin -O linux -T kernel \
			-C gzip -a 0x1000 -e 0x1000 -n "uClinux Kernel and Filesystem" \
			-d $(IMAGE).bin.gz $(IMAGEDIR)/uImage; \
		rm $(IMAGE).bin.gz; \
		if [ -z "$(CONFIG_MTD_UCLINUX)" ]; then \
			$(CROSS_COMPILE)objcopy -O binary -S $(ROOTDIR)/$(LINUXDIR)/vmlinux \
				$(IMAGEDIR)/vmlinux.bin; \
			gzip -f9 $(IMAGEDIR)/vmlinux.bin; \
			$(CROSS_COMPILE)mkimage -A blackfin -O linux -T kernel \
				-C gzip -a 0x1000 -e 0x1000 -n "uClinux Kernel Only Image" \
				-d $(IMAGEDIR)/vmlinux.bin.gz  $(IMAGEDIR)/vmImage; \
			rm  $(IMAGEDIR)/vmlinux.bin.gz; \
		fi ; \
	fi

clean:
