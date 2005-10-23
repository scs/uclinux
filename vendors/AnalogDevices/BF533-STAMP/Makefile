#
#	Makefile -- Build instructions for the BF533-STAMP from ADI
#

ROMFSIMG = $(IMAGEDIR)/rootfs.img
JFFS2IMG = $(IMAGEDIR)/jffs2.img
IMAGE    = $(IMAGEDIR)/linux

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
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	if [ -x $(MKFS_JFFS2) ]; then \
		$(MKFS_JFFS2) -d $(ROMFSDIR) -D device_table.txt -o $(JFFS2IMG); \
	fi
	./bfin-elf-genext2fs -i $(INODES) -b $(BLOCKS) -d $(ROMFSDIR) -D device_table.txt $(ROMFSIMG)
	cp $(ROOTDIR)/$(LINUXDIR)/linux $(IMAGEDIR)
	BSS=`set -- \`$(CROSS_COMPILE)objdump -h $(IMAGEDIR)/linux | grep .bss\` ; echo 0x$${4}` ; \
	BSS_SIZE=`set -- \`$(CROSS_COMPILE)objdump -h $(IMAGEDIR)/linux | grep .bss\` ; echo 0x$${3}` ; \
	ADDR=$$(($$BSS + $$BSS_SIZE)) ; \
	$(CROSS_COMPILE)objcopy --add-section .romfs=$(IMAGEDIR)/rootfs.img \
	--adjust-section-vma .romfs=$${ADDR} --no-adjust-warnings \
	--set-section-flags .romfs=alloc,load,data \
	$(IMAGEDIR)/linux concat.dxe
	mv concat.dxe $(IMAGE)

clean:
