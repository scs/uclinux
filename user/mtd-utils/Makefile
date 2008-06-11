# version is based on current git snapshot from here (since releases are not
# really made anymore by the mtd guys):
# http://git.infradead.org/?p=mtd-utils.git;a=summary
VER = 1fd1b5430221b99e05d4f63693ccb0ec11a4af7c

RAWTARGETS-y :=
RAWTARGETS-$(CONFIG_USER_MTDUTILS_ERASE)        += flash_erase
RAWTARGETS-$(CONFIG_USER_MTDUTILS_ERASEALL)     += flash_eraseall
RAWTARGETS-$(CONFIG_USER_MTDUTILS_FTL_CHECK)    += ftl_check
RAWTARGETS-$(CONFIG_USER_MTDUTILS_FTL_FORMAT)   += ftl_format
RAWTARGETS-$(CONFIG_USER_MTDUTILS_NFTL_FORMAT)  += nftl_format
RAWTARGETS-$(CONFIG_USER_MTDUTILS_NFTLDUMP)     += nftldump
RAWTARGETS-$(CONFIG_USER_MTDUTILS_NANDDUMP)     += nanddump
RAWTARGETS-$(CONFIG_USER_MTDUTILS_NANDTEST)     += nandtest
RAWTARGETS-$(CONFIG_USER_MTDUTILS_NANDWRITE)    += nandwrite
RAWTARGETS-$(CONFIG_USER_MTDUTILS_DOC_LOADBIOS) += doc_loadbios
RAWTARGETS-$(CONFIG_USER_MTDUTILS_DOC_LOADIPL)  += doc_loadipl
RAWTARGETS-$(CONFIG_USER_MTDUTILS_MKFSJFFS)     += mkfs.jffs
RAWTARGETS-$(CONFIG_USER_MTDUTILS_MKFSJFFS2)    += mkfs.jffs2

# Host based builds needed for constructing host images
BUILDTARGETS-y := mkfs.jffs2
BUILDTARGETS-$(CONFIG_JFFS_FS)  += mkfs.jffs
BUILDTARGETS-$(CONFIG_JFFS2_FS) += mkfs.jffs2

MAKE_MTD = $(MAKE) -C $(VER) WITHOUT_XATTR=1
all:
	unset CC CFLAGS CPPFLAGS CROSS LDFLAGS; $(MAKE_MTD) BUILDDIR=$$PWD/build-$(VER)-host RAWTARGETS="$(BUILDTARGETS-y)"
	for f in $(BUILDTARGETS-y) ; do ln -sf build-$(VER)-host/$$f $$f ; done

	$(MAKE_MTD) BUILDDIR=$$PWD/build-$(VER) RAWTARGETS="$(RAWTARGETS-y)"

clean:
	rm -rf build-$(VER)*
	rm -f mkfs.jffs mkfs.jffs2

romfs:
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_ERASE        build-$(VER)/flash_erase /bin/flash_erase
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_ERASEALL     build-$(VER)/flash_eraseall /bin/flash_eraseall
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_FTL_CHECK    build-$(VER)/ftl_check /bin/ftl_check
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_FTL_FORMAT   build-$(VER)/ftl_format /bin/ftl_format
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_MKFSJFFS     build-$(VER)/mkfs.jffs /bin/mkfs.jffs
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_MKFSJFFS2    build-$(VER)/mkfs.jffs2 /bin/mkfs.jffs2
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NFTLDUMP     build-$(VER)/nftldump /bin/nftldump
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NFTL_FORMAT  build-$(VER)/nftl_format /bin/nftl_format
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NANDDUMP     build-$(VER)/nanddump /bin/nanddump
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NANDTEST     build-$(VER)/nandtest /bin/nandtest
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NANDWRITE    build-$(VER)/nandwrite /bin/nandwrite
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_DOC_LOADBIOS build-$(VER)/doc_loadbios /bin/doc_loadbios
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_DOC_LOADIPL  build-$(VER)/doc_loadipl /bin/doc_loadipl
