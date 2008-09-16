#
#	Makefile -- Build instructions for Aglaia/Tepla
#

ROMFSIMG = $(IMAGEDIR)/rootfs.img
JFFS2IMG = $(IMAGEDIR)/jffs2.img
IMAGE    = $(IMAGEDIR)/linux

UBOOT_DIR := $(ROOTDIR)/../u-boot_1.1.3

MKFS_JFFS2 = $(ROOTDIR)/user/mtd-utils/build/mkfs.jffs2

# Blocks must be a multiple of 256
BLOCKS   = 4096
INODES   = 1024

ROMFS_DIRS = bin dev etc etc/dhcpc home lib mnt proc usr var root home tmp home/httpd home/httpd/cgi-bin etc/boa /etc/config var/run var/lib/misc var/log/boa

romfs:
	[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
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
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image:
	if [ -x $(MKFS_JFFS2) ]; then \
		$(MKFS_JFFS2) -d $(ROMFSDIR) -D device_table.txt -o $(JFFS2IMG); \
	fi
	bfin-uclinux-objcopy -O binary $(ROOTDIR)/$(LINUXDIR)/vmlinux $(ROOTDIR)/$(LINUXDIR)/vmlinux.bin
	rm -f $(ROOTDIR)/$(LINUXDIR)/vmlinux.bin.gz
	gzip -9 $(ROOTDIR)/$(LINUXDIR)/vmlinux.bin
	$(CROSS_COMPILE)mkimage -A blackfin -O linux -T kernel -C gzip -a 0x1000 -e 0x1000 -n "uClinux Kernel Image" -d $(ROOTDIR)/$(LINUXDIR)/vmlinux.bin.gz $(ROOTDIR)/$(LINUXDIR)/uImage

old-image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	if [ -x $(MKFS_JFFS2) ]; then \
		$(MKFS_JFFS2) -d $(ROMFSDIR) -D device_table.txt -o $(JFFS2IMG); \
	fi
	./bfin-elf-genext2fs -i $(INODES) -b $(BLOCKS) -d $(ROMFSDIR) -D device_table.txt $(ROMFSIMG)
	cp $(ROMFSIMG) $(ROOTDIR)/$(LINUXDIR)/
	BSS=`set -- \`$(CROSS_COMPILE)objdump -h $(ROOTDIR)/$(LINUXDIR)/linux | grep .bss\` ; echo 0x$${4}` ; \
	BSS_SIZE=`set -- \`$(CROSS_COMPILE)objdump -h $(ROOTDIR)/$(LINUXDIR)/linux | grep .bss\` ; echo 0x$${3}` ; \
	ADDR=$$(($$BSS + $$BSS_SIZE)) ; \
	$(CROSS_COMPILE)objcopy --add-section .romfs=$(ROOTDIR)/$(LINUXDIR)/rootfs.img \
	--adjust-section-vma .romfs=$${ADDR} --no-adjust-warnings \
	--set-section-flags .romfs=alloc,load,data \
	$(ROOTDIR)/$(LINUXDIR)/linux concat.dxe
	cp concat.dxe $(IMAGE)
	mv concat.dxe $(ROOTDIR)/$(LINUXDIR)/linux

clean:
