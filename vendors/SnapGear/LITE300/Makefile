#
#	Makefile -- Build instructions for Kendin/Micrel/KS8695
#

KERNELZ  = $(IMAGEDIR)/zImage
RAMDISK  = $(IMAGEDIR)/ramdisk
RAMDISKZ = $(IMAGEDIR)/ramdisk.gz
IMAGE    = $(IMAGEDIR)/image.bin
IMAGEZ   = $(IMAGEDIR)/imagez.bin

ROMFS_DIRS = \
	bin \
	dev dev/flash \
	etc etc/config \
	home home/httpd home/httpd/cgi-bin \
	lib lib/modules \
	mnt \
	proc \
	sbin \
	usr usr/bin usr/sbin \
	var

DEVICES = \
	mem,c,1,1	kmem,c,1,2	null,c,1,3 \
	zero,c,1,5	random,c,1,8	urandom,c,1,9 \
	ram0,b,1,0	ram1,b,1,1	ram2,b,1,2 	ram3,b,1,3 \
	\
	tty,c,5,0	console,c,5,1 \
	cua0,c,5,64	cua1,c,5,65 \
	ttyS0,c,4,64	ttyS1,c,4,65 \
	ttyAM0,c,204,16	ttyAM1,c,204,17 \
	\
	ptyp0,c,2,0	ptyp1,c,2,1	ptyp2,c,2,2	ptyp3,c,2,3 \
	ptyp4,c,2,4	ptyp5,c,2,5	ptyp6,c,2,6	ptyp7,c,2,7 \
	ptyp8,c,2,8	ptyp9,c,2,9	ptypa,c,2,10	ptypb,c,2,11 \
	ptypc,c,2,12	ptypd,c,2,13	ptype,c,2,14	ptypf,c,2,15 \
	\
	ptyq0,c,2,16	ptyq1,c,2,17	ptyq2,c,2,18	ptyq3,c,2,19 \
	ptyq4,c,2,20	ptyq5,c,2,21	ptyq6,c,2,22	ptyq7,c,2,23 \
	ptyq8,c,2,24	ptyq9,c,2,25	ptyqa,c,2,26	ptyqb,c,2,27 \
	ptyqc,c,2,28	ptyqd,c,2,29	ptyqe,c,2,30	ptyqf,c,2,31 \
	\
	ptys0,c,2,48	ptys1,c,2,49	ptys2,c,2,50	ptys3,c,2,51 \
	ptys4,c,2,52	ptys5,c,2,53	ptys6,c,2,54	ptys7,c,2,55 \
	ptys8,c,2,56	ptys9,c,2,57	ptysa,c,2,58	ptysb,c,2,59 \
	ptysc,c,2,60	ptysd,c,2,61	ptyse,c,2,62	ptysf,c,2,63 \
        \
	ttyp0,c,3,0	ttyp1,c,3,1	ttyp2,c,3,2	ttyp3,c,3,3 \
	ttyp4,c,3,4	ttyp5,c,3,5	ttyp6,c,3,6	ttyp7,c,3,7 \
	ttyp8,c,3,8	ttyp9,c,3,9	ttypa,c,3,10	ttypb,c,3,11 \
	ttypc,c,3,12	ttypd,c,3,13	ttype,c,3,14	ttypf,c,3,15 \
	\
	ttyq0,c,3,16	ttyq1,c,3,17	ttyq2,c,3,18	ttyq3,c,3,19 \
	ttyq4,c,3,20	ttyq5,c,3,21	ttyq6,c,3,22	ttyq7,c,3,23 \
	ttyq8,c,3,24	ttyq9,c,3,25	ttyqa,c,3,26	ttyqb,c,3,27 \
	ttyqc,c,3,28	ttyqd,c,3,29	ttyqe,c,3,30	ttyqf,c,3,31 \
	\
	ttyr0,c,3,32	ttyr1,c,3,33	ttyr2,c,2,34	ttyr3,c,2,35 \
	ttyr4,c,3,36	ttyr5,c,3,37	ttyr6,c,2,38	ttyr7,c,2,39 \
	ttyr8,c,3,40	ttyr9,c,3,41	ttyra,c,2,42	ttyrb,c,2,43 \
	ttyrc,c,3,44	ttyrd,c,3,45	ttyre,c,2,46	ttyrf,c,2,47 \
	\
	ttys0,c,3,48	ttys1,c,3,49	ttys2,c,3,50	ttys3,c,3,51 \
	ttys4,c,3,52	ttys5,c,3,53	ttys6,c,3,54	ttys7,c,3,55 \
	ttys8,c,3,56	ttys9,c,3,57	ttysa,c,3,58	ttysb,c,3,59 \
	ttysc,c,3,60	ttysd,c,3,61	ttyse,c,3,62	ttysf,c,3,63 \
        \
	mtd0,c,90,0	mtdr0,c,90,1	mtdblock0,b,31,0 \
	mtd1,c,90,2	mtdr1,c,90,3	mtdblock1,b,31,1 \
	mtd2,c,90,4	mtdr2,c,90,5	mtdblock2,b,31,2 \
	mtd3,c,90,6	mtdr3,c,90,7	mtdblock3,b,31,3 \
	mtd4,c,90,8	mtdr4,c,90,9	mtdblock4,b,31,4 \
	mtd5,c,90,10	mtdr5,c,90,11	mtdblock5,b,31,5 \
	mtd6,c,90,12	mtdr6,c,90,13	mtdblock6,b,31,6 \
	mtd7,c,90,14	mtdr7,c,90,15	mtdblock7,b,31,7 \
	mtd8,c,90,16	mtdr8,c,90,17	mtdblock8,b,31,8 \
	mtd9,c,90,18	mtdr9,c,90,19	mtdblock9,b,31,9 \
	\
	ipsec,c,36,10 \
	ledman,c,126,0 \
	ppp,c,108,0

FLASH_DEVICES = \
	boot,c,90,10 \
	image,c,90,6 \
	config,c,90,4

clean:
	-rm -f mkcramfs

romfs:
	[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	for i in $(DEVICES); do \
		touch $(ROMFSDIR)/dev/@$$i; \
	done
	for i in $(FLASH_DEVICES); do \
		touch $(ROMFSDIR)/dev/flash/@$$i; \
	done
	$(ROMFSINST) ../../SecureEdge/romfs_x86 /
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/tmp/log /dev/log
	$(ROMFSINST) /etc/rc
	echo "ttyAM0::respawn:/sbin/getty 115200 -" >> $(ROMFSDIR)/etc/default/inittab
	chmod 755 $(ROMFSDIR)/etc/default/dhcpcd-eth0.exe
	chmod 755 $(ROMFSDIR)/etc/default/dhcpcd-eth1.exe
	chmod 755 $(ROMFSDIR)/etc/default/ip-up $(ROMFSDIR)/etc/default/ip-down
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

mkcramfs: $(ROOTDIR)/user/cramfs/mkcramfs.c
	$(HOSTCC) -o $@ -I$(ROOTDIR)/$(LINUXDIR)/include $< -lz

image: mkcramfs
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	cp $(ROOTDIR)/$(LINUXDIR)/arch/arm/boot/zImage $(KERNELZ)

	#genext2fs -b 5120 -f dev.txt -d $(ROMFSDIR) $(RAMDISK)
	#gzip -9 -f $(RAMDISK)

	./mkcramfs -z -r $(ROMFSDIR) $(RAMDISK)
	cp $(RAMDISK) $(RAMDISKZ)

	SIZE=`wc -c $(KERNELZ) | awk '{ print $$1 }'` ; \
	PAD=`expr 917504 - $$SIZE` ; \
	dd if=/dev/zero count=1 bs=$$PAD 2> /dev/null | tr \\000 \\377 >> $(IMAGE)
	cp $(KERNELZ) $(IMAGE)
	cat $(RAMDISKZ) >> $(IMAGE)
	gzip -9 < $(IMAGE) > $(IMAGEZ)

	echo -ne "\000" >> $(IMAGEZ)
	echo -n $(VERSIONPKG) >> $(IMAGEZ)
	echo -ne "\000" >> $(IMAGEZ)
	echo -n $(CONFIG_VENDOR) >> $(IMAGEZ)
	echo -ne "\000" >> $(IMAGEZ)
	echo -n $(CONFIG_PRODUCT) >> $(IMAGEZ)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGEZ) >> $(IMAGEZ)

	if [ -d /tftpboot ]; then \
		cp $(KERNELZ) /tftpboot/ 2> /dev/null; \
		cp $(RAMDISKZ) /tftpboot/ 2> /dev/null; \
		cp $(IMAGEZ) /tftpboot/ 2> /dev/null; \
	fi

