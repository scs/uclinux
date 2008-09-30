############################################################################
#
# Allow people to quickly sync their staging directory with the actual
# toolchain as this will allow them to transparently build external apps
# against libraries from uClinux-dist.  Maybe hook in tools/autotools.mk to
# mung pkgconfig/-config/*.la/etc... paths ?
#

SYSROOT_LIBDIR = $(shell $(CONFIGURE_HOST)-gcc $(CPUFLAGS) -print-file-name=libc.a | sed 's:/usr/lib/libc.a$$::')
vendor_staging_install:
ifeq ($(SYSROOT_LIBDIR),)
	@echo "SYSROOT_LIBDIR is not set -- toolchain problem ?"
	@false
else
	cp -a $(STAGEDIR)/* $(SYSROOT_LIBDIR)/
endif

############################################################################
#
# Copy the FDPIC ELF and Shared FLAT libraries as requested/needed according
# to the user configuration options
#

romfs.shared.libs:
ifeq ($(CONFIG_INSTALL_ELF_SHARED_LIBS),y)
	set -e; \
	t=`bfin-linux-uclibc-gcc $(CPUFLAGS) -print-file-name=libc.a`; \
	t=`dirname $$t`/../..; \
	for i in $$t/lib/*so*; do \
		bn=`basename $$i`; \
		if [ -f $$i ] ; then \
			$(ROMFSINST) -p 755 $$i /lib/$$bn; \
		fi; \
	done; \
	for i in $$t/lib/*so*; do \
		if [ -h $$i -a -e $$i ] ; then \
			j=`readlink $$i`; \
			$(ROMFSINST) -s \
				`basename $$j` \
				/lib/`basename $$i`; \
		fi; \
	done; \
	if [ "$(CONFIG_INSTALL_ELF_TRIM_LIBS)" = "y" ] ; then \
		$(ROOTDIR)/vendors/AnalogDevices/trim-libs.sh; \
	fi; \
	if type bfin-linux-uclibc-ldconfig >/dev/null 2>&1; then \
		bfin-linux-uclibc-ldconfig -r $(ROMFSDIR); \
	fi
endif
ifeq ($(CONFIG_INSTALL_FLAT_SHARED_LIBS),y)
	set -e; \
	t=`bfin-uclinux-gcc $(CPUFLAGS) -mid-shared-library -print-file-name=libc`; \
	if [ -f $$t -a ! -h $$t ] ; then \
		$(ROMFSINST) -p 755 $$t /lib/lib1.so; \
	fi
endif

############################################################################
#
# File system targets
#

IMAGE_ROMFS_BASE = $(IMAGEDIR)/rootfs

.PHONY: image.rootfs.cramfs image.rootfs.cramfs.force
MKFS_CRAMFS_FLAGS ?= -z
image.rootfs.cramfs.force:
	$(MKFS_CRAMFS) $(MKFS_CRAMFS_FLAGS) -D $(DEVICE_TABLE) $(ROMFSDIR) $(IMAGE_ROMFS_BASE).cramfs
ifeq ($(CONFIG_CRAMFS),y)
image.rootfs.cramfs: image.rootfs.cramfs.force
endif

.PHONY: image.rootfs.ext2 image.rootfs.ext2.force
MKFS_EXT2_FLAGS ?= -m 0 -i $(EXT2_INODES) -b $(EXT2_BLOCKS)
image.rootfs.ext2.force:
	$(MKFS_EXT2) $(MKFS_EXT2_FLAGS) -d $(ROMFSDIR) -D $(DEVICE_TABLE) $(IMAGE_ROMFS_BASE).ext2
ifeq ($(CONFIG_EXT2_FS),y)
image.rootfs.ext2: image.rootfs.ext2.force
endif

.PHONY: image.rootfs.initramfs image.rootfs.initramfs.force
image.rootfs.initramfs.force:
	/bin/bash $(ROOTDIR)/$(LINUXDIR)/scripts/gen_initramfs_list.sh -u squash -g squash $(ROMFSDIR) > $(IMAGE_ROMFS_BASE).initramfs.contents
	awk -f $(ROOTDIR)/tools/dev-table-to-cpio.awk $(DEVICE_TABLE) >> $(IMAGE_ROMFS_BASE).initramfs.contents
	echo "slink /init /sbin/init 0755 0 0" >> $(IMAGE_ROMFS_BASE).initramfs.contents
	$(ROOTDIR)/$(LINUXDIR)/usr/gen_init_cpio $(IMAGE_ROMFS_BASE).initramfs.contents > $(IMAGE_ROMFS_BASE).initramfs
	gzip -c -9 $(IMAGE_ROMFS_BASE).initramfs > $(IMAGE_ROMFS_BASE).initramfs.gz
ifneq ($(CONFIG_MTD_UCLINUX),y)
ifeq ($(CONFIG_BLK_DEV_INITRD),y)
image.rootfs.initramfs: image.rootfs.initramfs.force
endif
endif

.PHONY: image.rootfs.jffs2 image.rootfs.jffs2.force
MKFS_JFFS2_FLAGS ?= -l
image.rootfs.jffs2.force:
	$(MKFS_JFFS2) $(MKFS_JFFS2_FLAGS) -d $(ROMFSDIR) -D $(DEVICE_TABLE) -o $(IMAGE_ROMFS_BASE).jffs2
ifeq ($(CONFIG_JFFS2_FS),y)
image.rootfs.jffs2: image.rootfs.jffs2.force
endif

.PHONY: image.rootfs.romfs image.rootfs.romfs.force
MKFS_ROMFS_FLAGS ?=
image.rootfs.romfs.force:
	set -e ; \
	$(ROOTDIR)/tools/mkdevdir.sh $(ROMFSDIR) $(DEVICE_TABLE); \
	$(MKFS_ROMFS) $(MKFS_ROMFS_FLAGS) -f $(IMAGE_ROMFS_BASE).romfs -d $(ROMFSDIR); \
	rm -rf $(ROMFSDIR)/dev/*
ifeq ($(CONFIG_ROMFS_FS),y)
image.rootfs.romfs: image.rootfs.romfs.force
endif

.PHONY: image.rootfs.yaffs image.rootfs.yaffs.force
MKFS_YAFFS_FLAGS ?=
image.rootfs.yaffs.force:
	$(MKFS_YAFFS) $(MKFS_YAFFS_FLAGS) $(ROMFSDIR) $(IMAGE_ROMFS_BASE).yaffs > /dev/null
ifeq ($(CONFIG_YAFFS_FS),y)
image.rootfs.yaffs: image.rootfs.yaffs.force
endif

.PHONY: image.rootfs.yaffs2 image.rootfs.yaffs2.force
MKFS_YAFFS2_FLAGS ?=
image.rootfs.yaffs2.force:
	$(MKFS_YAFFS2) $(MKFS_YAFFS2_FLAGS) $(ROMFSDIR) $(IMAGE_ROMFS_BASE).yaffs2 > /dev/null
ifeq ($(CONFIG_YAFFS_FS),y)
image.rootfs.yaffs2: image.rootfs.yaffs2.force
endif

.PHONY: image.rootfs.all
image.rootfs.all: \
	image.rootfs.cramfs \
	image.rootfs.ext2 \
	image.rootfs.initramfs \
	image.rootfs.jffs2 \
	image.rootfs.romfs \
	image.rootfs.yaffs \
	image.rootfs.yaffs2

############################################################################
#
# Kernel targets (ELF)
#

IMAGE_KERNEL = $(IMAGEDIR)/vmlinux
IMAGE_KERNEL_BASE = $(IMAGEDIR)/linux
ROMFS_ADDR = $$($(CROSS_COMPILE)readelf -s $(IMAGE_KERNEL) | awk '$$NF == "__end" {print "0x"$$2}')
MAKE_KERNEL_ROMFS = \
	$(OBJCOPY) --add-section .romfs=$(IMAGE_ROMFS_BASE).$(1) \
		--adjust-section-vma .romfs=$(ROMFS_ADDR) --no-adjust-warnings \
		--set-section-flags .romfs=alloc,load,data $(IMAGE_KERNEL) $(IMAGE_KERNEL_BASE).$(1)

.PHONY: image.kernel.cramfs image.kernel.cramfs.force
image.kernel.cramfs.force: image.kernel.vmlinux
	$(call MAKE_KERNEL_ROMFS,cramfs)
ifeq ($(CONFIG_CRAMFS),y)
image.kernel.cramfs: image.kernel.cramfs.force
endif

.PHONY: image.kernel.ext2 image.kernel.ext2.force
image.kernel.ext2.force: image.kernel.vmlinux
	$(call MAKE_KERNEL_ROMFS,ext2)
ifeq ($(CONFIG_EXT2_FS),y)
image.kernel.ext2: image.kernel.ext2.force
endif

.PHONY: image.kernel.romfs image.kernel.romfs.force
image.kernel.romfs.force: image.kernel.vmlinux
	$(call MAKE_KERNEL_ROMFS,romfs)
ifeq ($(CONFIG_ROMFS_FS),y)
image.kernel.romfs: image.kernel.romfs.force
endif

.PHONY: image.kernel.vmlinux
$(IMAGE_KERNEL): $(ROOTDIR)/$(LINUXDIR)/vmlinux
	cp $< $@
	$(STRIP) -g $@
image.kernel.vmlinux: $(IMAGE_KERNEL)

.PHONY: image.kernel.all
ifeq ($(CONFIG_MTD_UCLINUX),y)
image.kernel.all: \
	image.kernel.cramfs \
	image.kernel.ext2 \
	image.kernel.romfs
image.kernel.all:
# create default "linux" symlink
	for fs in cramfs ext2 romfs ; do \
		if [ -e "$(IMAGE_KERNEL_BASE).$$fs" ] ; then \
			ln -sf "linux.$$fs" "$(IMAGE_KERNEL_BASE)" ; \
		fi ; \
	done
endif
image.kernel.all: \
	image.kernel.vmlinux

############################################################################
#
# Kernel targets (uImage)
#

LINUXBOOTDIR = $(ROOTDIR)/$(LINUXDIR)/arch/$(ARCH)/boot
IMAGE_UIMAGE_BASE = $(IMAGEDIR)/uImage
KERNEL_ENTRY = $$($(CROSS_COMPILE)nm $(IMAGE_KERNEL_BASE).$(1) | awk '$$NF == "__start" {print $$1}')
MAKE_UIMAGE_ROMFS = \
	set -e; \
	$(OBJCOPY) -O binary -S $(IMAGE_KERNEL_BASE).$(1) $(IMAGE_KERNEL_BASE).bin; \
	gzip -f9 $(IMAGE_KERNEL_BASE).bin; \
	$(MKIMAGE) -A blackfin -O linux -T kernel \
		-C gzip -a $(CONFIG_BOOT_LOAD) -e $(call KERNEL_ENTRY,$(1)) -n "Linux Kernel and $(1)" \
		-d $(IMAGE_KERNEL_BASE).bin.gz $(IMAGE_UIMAGE_BASE).$(1); \
	rm $(IMAGE_KERNEL_BASE).bin.gz

.PHONY: image.uimage.cramfs image.uimage.cramfs.force
image.uimage.cramfs.force:
	$(call MAKE_UIMAGE_ROMFS,cramfs)
ifeq ($(CONFIG_CRAMFS),y)
image.uimage.cramfs: image.uimage.cramfs.force
endif

.PHONY: image.uimage.ext2 image.uimage.ext2.force
image.uimage.ext2.force:
	$(call MAKE_UIMAGE_ROMFS,ext2)
ifeq ($(CONFIG_EXT2_FS),y)
image.uimage.ext2: image.uimage.ext2.force
endif

.PHONY: image.uimage.initramfs
image.uimage.initramfs:
# first one set with the rootfs compressed (to work with uncompressed kernel)
	cp $(IMAGE_ROMFS_BASE).initramfs.gz $(ROOTDIR)/$(LINUXDIR)/usr/initramfs_data.cpio.gz
	CPPFLAGS="" CFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -j$(HOST_NCPU) -C $(ROOTDIR)/$(LINUXDIR)
	cp $(LINUXBOOTDIR)/vmImage $(IMAGE_UIMAGE_BASE).initramfs.gz
	cp $(ROOTDIR)/$(LINUXDIR)/System.map $(IMAGEDIR)/System.map.initramfs.gz
	cp $(ROOTDIR)/$(LINUXDIR)/vmlinux $(IMAGE_KERNEL_BASE).initramfs.gz
	$(STRIP) -g $(IMAGE_KERNEL_BASE).initramfs.gz
	ln -sf linux.initramfs.gz $(IMAGE_KERNEL_BASE)

# then one set with the rootfs uncompressed (since u-boot images do compression)
# we want to do this step last since it will leave the kernel dir in a state
# that properly reflects the default uImage
	cp $(IMAGE_ROMFS_BASE).initramfs $(ROOTDIR)/$(LINUXDIR)/usr/initramfs_data.cpio.gz
	CPPFLAGS="" CFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -j$(HOST_NCPU) -C $(ROOTDIR)/$(LINUXDIR)
	cp $(LINUXBOOTDIR)/vmImage $(IMAGE_UIMAGE_BASE).initramfs
	cp $(ROOTDIR)/$(LINUXDIR)/System.map $(IMAGEDIR)/System.map.initramfs
	cp $(ROOTDIR)/$(LINUXDIR)/vmlinux $(IMAGE_KERNEL_BASE).initramfs
	$(STRIP) -g $(IMAGE_KERNEL_BASE).initramfs
	ln -sf uImage.initramfs $(IMAGE_UIMAGE_BASE)

.PHONY: image.uimage.romfs image.uimage.romfs.force
image.uimage.romfs.force:
	$(call MAKE_UIMAGE_ROMFS,romfs)
ifeq ($(CONFIG_ROMFS_FS),y)
image.uimage.romfs: image.uimage.romfs.force
endif

# this should be handled by the kernel build already ...
# but in case something failed, let's help the user out
$(LINUXBOOTDIR)/vmImage:
	@printf "\nYour kernel directory '$(LINUXDIR)' lacks a vmImage file:\n"; \
	 printf "\t$@\n"; \
	 printf "This usually means your toolchain lacks u-boot tools.  Please check your\n"; \
	 printf "toolchain installation.  The file is generated when running 'make linux'.\n\n"; \
	 false

.PHONY: image.uimage.vmimage
$(IMAGEDIR)/vmImage: $(LINUXBOOTDIR)/vmImage
	cp $< $@
image.uimage.vmimage: $(IMAGEDIR)/vmImage

.PHONY: image.uimage.all
image.uimage.all: \
	image.uimage.vmimage
ifeq ($(CONFIG_MTD_UCLINUX),y)
image.uimage.all: \
	image.uimage.cramfs \
	image.uimage.ext2 \
	image.uimage.romfs
image.uimage.all:
# create default "uImage" symlink
	for fs in cramfs ext2 romfs ; do \
		if [ -e "$(IMAGE_UIMAGE_BASE).$$fs" ] ; then \
			ln -sf "uImage.$$fs" "$(IMAGE_UIMAGE_BASE)" ; \
		fi ; \
	done
else
ifeq ($(CONFIG_BLK_DEV_INITRD),y)
image.uimage.all: \
	image.uimage.initramfs
endif
endif

############################################################################
#
# Allow people to hit any of these vendor targets via "vendor_" prefix
#

vendor_%:
	$(MAKE) $(patsubst vendor_%,%,$@)

############################################################################
#
# Allow people to create custom rules in vendor/AnalogDevices/<board>/
# without having to change the Makefile in the dist
#

-include Makefile.local
