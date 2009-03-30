# version is based on current git snapshot from here (since releases are not
# really made anymore by the mtd guys):
GITWEB = http://git.infradead.org/?p=$(GITREPO).git
GITREPO = mtd-utils
VER = 606f38a2221648ca5c5fa292c9f71d2ddd59fa66

TARGETS-y :=
TARGETS-$(CONFIG_USER_MTDUTILS_ERASE)        += flash_erase
TARGETS-$(CONFIG_USER_MTDUTILS_ERASEALL)     += flash_eraseall
TARGETS-$(CONFIG_USER_MTDUTILS_FTL_CHECK)    += ftl_check
TARGETS-$(CONFIG_USER_MTDUTILS_FTL_FORMAT)   += ftl_format
TARGETS-$(CONFIG_USER_MTDUTILS_NFTL_FORMAT)  += nftl_format
TARGETS-$(CONFIG_USER_MTDUTILS_NFTLDUMP)     += nftldump
TARGETS-$(CONFIG_USER_MTDUTILS_NANDDUMP)     += nanddump
TARGETS-$(CONFIG_USER_MTDUTILS_NANDTEST)     += nandtest
TARGETS-$(CONFIG_USER_MTDUTILS_NANDWRITE)    += nandwrite
TARGETS-$(CONFIG_USER_MTDUTILS_DOC_LOADBIOS) += doc_loadbios
TARGETS-$(CONFIG_USER_MTDUTILS_DOC_LOADIPL)  += doc_loadipl
TARGETS-$(CONFIG_USER_MTDUTILS_MKFSJFFS)     += mkfs.jffs
TARGETS-$(CONFIG_USER_MTDUTILS_MKFSJFFS2)    += mkfs.jffs2

UBI_UTILS_TARGETS-m :=
UBI_UTILS_TARGETS-y :=
UBI_UTILS_TARGETS-$(CONFIG_USER_MTDUTILS_UBIUTILS) += ubiupdatevol ubimkvol ubirmvol ubicrc32 ubinfo ubiattach ubidetach ubinize ubiformat ubirename
UBI_UTILS_TARGETS = $(UBI_UTILS_TARGETS-m) $(UBI_UTILS_TARGETS-y)

# Host based builds needed for constructing host images
BUILDTARGETS-m :=
BUILDTARGETS-y :=
BUILDTARGETS-$(CONFIG_JFFS_FS)  += mkfs.jffs
BUILDTARGETS-$(CONFIG_JFFS2_FS) += mkfs.jffs2
BUILDTARGETS-$(CONFIG_JFFS2_SUMMARY) += sumtool
BUILDTARGETS = $(BUILDTARGETS-m) $(BUILDTARGETS-y)

UBI_MKFS_TARGETS-m :=
UBI_MKFS_TARGETS-y :=
UBI_MKFS_TARGETS-$(CONFIG_UBIFS_FS) += mkfs.ubifs
UBI_MKFS_TARGETS = $(UBI_MKFS_TARGETS-m) $(UBI_MKFS_TARGETS-y)

define MAKE_MTD
	$(MAKE) -C $(VER)/$(2) WITHOUT_XATTR=1 SUBDIRS= BUILDDIR=$$PWD/build-$(VER)$(4)/$(2) TARGETS="$(1)" CFLAGS="$(3) -I $(STAGEDIR)/include/ -L $(STAGEDIR)/lib/"
endef
define MAKE_HOST_MTD
	unset CC CFLAGS CPPFLAGS CROSS LDFLAGS; $(call MAKE_MTD,$(1),$(2),,-host)
	for f in $(1) ; do ln -sf build-$(VER)-host/$(2)/$$f $$f ; done
endef
all:
	$(call MAKE_HOST_MTD,$(BUILDTARGETS))
	$(call MAKE_HOST_MTD,$(UBI_MKFS_TARGETS),mkfs.ubifs)
	$(call MAKE_MTD,$(UBI_UTILS_TARGETS),ubi-utils,$(CFLAGS))
	$(call MAKE_MTD,$(TARGETS-y),,$(CFLAGS))

clean:
	rm -rf build-$(VER)* mkfs.jffs mkfs.jffs2 mkfs.ubifs sumtool

romfs:
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_ERASE        build-$(VER)/flash_erase /bin/flash_erase
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_ERASEALL     build-$(VER)/flash_eraseall /bin/flash_eraseall
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_FTL_CHECK    build-$(VER)/ftl_check /bin/ftl_check
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_FTL_FORMAT   build-$(VER)/ftl_format /bin/ftl_format
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_MKFSJFFS     build-$(VER)/mkfs.jffs /bin/mkfs.jffs
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_MKFSJFFS2    build-$(VER)/mkfs.jffs2 /bin/mkfs.jffs2
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_UBIUTILS   build-$(VER)/ubi-utils/ubiformat /bin/ubiformat
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_UBIUTILS   build-$(VER)/ubi-utils/ubiattach /bin/ubiattach
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_UBIUTILS   build-$(VER)/ubi-utils/ubidetach /bin/ubidetach
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_UBIUTILS   build-$(VER)/ubi-utils/ubinfo /bin/ubinfo
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_UBIUTILS   build-$(VER)/ubi-utils/ubimkvol /bin/ubimkvol
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_UBIUTILS   build-$(VER)/ubi-utils/ubirmvol /bin/ubirmvol
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_UBIUTILS   build-$(VER)/ubi-utils/ubiupdatevol /bin/ubiupdatevol
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_UBIUTILS   build-$(VER)/ubi-utils/ubinize /bin/ubinize
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_UBIUTILS   build-$(VER)/ubi-utils/ubirename /bin/ubirename
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NFTLDUMP     build-$(VER)/nftldump /bin/nftldump
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NFTL_FORMAT  build-$(VER)/nftl_format /bin/nftl_format
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NANDDUMP     build-$(VER)/nanddump /bin/nanddump
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NANDTEST     build-$(VER)/nandtest /bin/nandtest
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NANDWRITE    build-$(VER)/nandwrite /bin/nandwrite
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_DOC_LOADBIOS build-$(VER)/doc_loadbios /bin/doc_loadbios
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_DOC_LOADIPL  build-$(VER)/doc_loadipl /bin/doc_loadipl

update:
	set -e ; \
	tar="$(dir $(GITWEB))`wget -q -O - '$(GITWEB)' | sed -n '/snapshot/{s:.*href="\([^"]*\).*:\1:;p;q}'`" ; \
	ver=`echo $$tar | sed 's:.*h=\([^;]*\).*:\1:'` ; \
	test "$(VER)" = "$$ver" && exit 0 ; \
	wget $$tar -O $(GITREPO).tar.gz ; \
	tar xf $(GITREPO).tar.gz ; \
	rm -rf $$ver ; \
	mv $(GITREPO) $$ver ; \
	rm $(GITREPO).tar.gz ; \
	sed -i "/^VER/s:=.*:= $$ver:" Makefile

.PHONY: all clean romfs update
