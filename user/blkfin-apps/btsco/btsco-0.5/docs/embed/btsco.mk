#############################################################
#
# bluezutils - User Space Program For Controling Bridging
#
#############################################################
#
BTSCO_SOURCE_URL=http://bluez.sourceforge.net/download
#BTSCO_SOURCE=btsco-0.4.tar.gz
BTSCO_BUILD_DIR=$(BUILD_DIR)/btsco
CVS_PASSFILE=/tmp/btscocvs

obj-m += snd-bt-sco.o
snd-bt-sco-objs := btsco.o

$(DL_DIR)/$(BTSCO_SOURCE):
	$(WGET) -P $(DL_DIR) $(BTSCO_SOURCE_URL)/$(BTSCO_SOURCE)

#$(BTSCO_BUILD_DIR)/.unpacked: $(DL_DIR)/$(BTSCO_SOURCE)
#	zcat $(DL_DIR)/$(BTSCO_SOURCE) | tar -C $(BUILD_DIR) -xf -
#	#$(SOURCE_DIR)/patch-kernel.sh $(BTSCO_LIBS_BUILD_DIR) $(SOURCE_DIR) bluez-libs*.patch
#	touch $(BTSCO_BUILD_DIR)/.unpacked

$(BTSCO_BUILD_DIR)/.unpacked:
	echo '/1 :pserver:anonymous@cvs.sourceforge.net:2401/cvsroot/bluetooth-alsa A' > $(CVS_PASSFILE)
	(cd $(BUILD_DIR); \
	CVS_PASSFILE=$(CVS_PASSFILE) \
	cvs -z3 -d:pserver:anonymous@cvs.sourceforge.net:/cvsroot/bluetooth-alsa co btsco )
	touch $(BTSCO_BUILD_DIR)/.unpacked

$(BTSCO_BUILD_DIR)/.configured: $(BTSCO_BUILD_DIR)/.unpacked
	(cd $(BTSCO_BUILD_DIR); rm -rf config.cache; ./bootstrap ; \
		$(TARGET_CONFIGURE_OPTS) CFLAGS="-DFORCE_LITTLE $(TARGET_CFLAGS)" \
		./configure \
		--target=$(GNU_TARGET_NAME) \
		--host=$(GNU_TARGET_NAME) \
		--build=$(GNU_HOST_NAME) \
		--with-bluez=$(STAGING_DIR)/usr \
		--prefix=/usr \
		--exec-prefix=/usr \
		--bindir=/usr/bin \
		--sbindir=/usr/sbin \
		--libexecdir=/usr/lib \
		--sysconfdir=/etc \
		--datadir=/usr/share \
		--localstatedir=/var \
		--mandir=/usr/man \
		--enable-fixed \
		--infodir=/usr/info );
	touch  $(BTSCO_BUILD_DIR)/.configured

$(BTSCO_BUILD_DIR)/btsco: $(BTSCO_BUILD_DIR)/.configured
	$(MAKE) -C $(BUILD_DIR)/linux-$(LINUX_VERSION) ARCH=arm CROSS_COMPILE=$(KERNEL_CROSS) CONFIG_SND_HWDEP=m modules
	$(MAKE) -C $(BUILD_DIR)/linux-$(LINUX_VERSION) ARCH=arm CROSS_COMPILE=$(KERNEL_CROSS) M=$(BTSCO_BUILD_DIR)/kernel modules
	$(MAKE) -C $(BTSCO_BUILD_DIR) 

# currently not exported to other packages
#$(STAGING_DIR)/usr/lib/libsbc.a: $(BTSCO_BUILD_DIR)/btsco
#	cp $(BTSCO_BUILD_DIR)/sbc/*.h $(BTSCO_BUILD_DIR)/sbc/libsbc.a $(STAGING_DIR)/usr/lib/

$(TARGET_DIR)/usr/bin/btsco: $(BTSCO_BUILD_DIR)/btsco
	cp $(BTSCO_BUILD_DIR)/kernel/snd-bt-sco.ko $(TARGET_DIR)/lib/modules/$(LINUX_VERSION)/kernel/sound/drivers/
	if [ -r $(BUILD_DIR)/linux-$(LINUX_VERSION)/System.map ]; then /sbin/depmod -ae -F $(BUILD_DIR)/linux-$(LINUX_VERSION)/System.map -b $(TARGET_DIR) -r $(LINUX_VERSION); fi 
	install -m 0755 $(BTSCO_BUILD_DIR)/a2recv $(TARGET_DIR)/usr/bin
	$(STRIP) --strip-unneeded $(TARGET_DIR)/usr/bin/a2recv
	install -m 0755 $(BTSCO_BUILD_DIR)/a2play $(TARGET_DIR)/usr/bin
	$(STRIP) --strip-unneeded $(TARGET_DIR)/usr/bin/a2play
	install -m 0755 $(BTSCO_BUILD_DIR)/btsco $(TARGET_DIR)/usr/bin
	$(STRIP) --strip-unneeded $(TARGET_DIR)/usr/bin/btsco

btsco-source: $(DL_DIR)/$(BTSCO_SOURCE)

btsco: uclibc $(TARGET_DIR)/usr/bin/btsco

btsco-clean:
	-$(MAKE) -C $(BTSCO_BUILD_DIR) clean

btsco-dirclean:
	rm -rf $(BTSCO_BUILD_DIR)
