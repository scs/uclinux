#
#	Makefile -- Build instructions for ADI/Blackfin
#

ROMFSIMG = $(IMAGEDIR)/rootfs.img
IMAGE    = $(IMAGEDIR)/linux

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
	$(ROMFSINST) /etc/bluetechnix.gif
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	bfin-elf-genext2fs -i $(INODES) -b $(BLOCKS) -d $(ROMFSDIR) -D device_table.txt $(ROMFSIMG)
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
