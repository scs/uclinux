VER = e2fsprogs-1.40.8

MAKE := $(MAKE) DVI=true MAKEINFO=true

CONF_OPTS = \
	--prefix=/ \
	--with-ldopts="$(LDFLAGS)"

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -E CONFIG_USER_E2FSPROGS_E2FSCK_E2FSCK $(STAGEDIR)/sbin/e2fsck /sbin/e2fsck
	rm -f $(ROMFSDIR)/bin/fsck.ext2 $(ROMFSDIR)/bin/fsck.ext3
	$(ROMFSINST) -E CONFIG_USER_E2FSPROGS_E2FSCK_E2FSCK -s e2fsck /sbin/fsck.ext2
	$(ROMFSINST) -E CONFIG_USER_E2FSPROGS_E2FSCK_E2FSCK -s e2fsck /sbin/fsck.ext3
	$(ROMFSINST) -E CONFIG_USER_E2FSPROGS_DEBUGFS_DEBUGFS $(STAGEDIR)/sbin/debugfs /sbin/debugfs
	$(ROMFSINST) -E CONFIG_USER_E2FSPROGS_MISC_BADBLOCKS $(STAGEDIR)/sbin/badblocks /sbin/badblocks
	$(ROMFSINST) -E CONFIG_USER_E2FSPROGS_MISC_CHATTR $(STAGEDIR)/bin/chattr /bin/chattr
	$(ROMFSINST) -E CONFIG_USER_E2FSPROGS_MISC_DUMPE2FS $(STAGEDIR)/sbin/dumpe2fs /sbin/dumpe2fs
	$(ROMFSINST) -E CONFIG_USER_E2FSPROGS_MISC_FSCK $(STAGEDIR)/sbin/fsck /sbin/fsck
	$(ROMFSINST) -E CONFIG_USER_E2FSPROGS_MISC_LSATTR $(STAGEDIR)/bin/lsattr /bin/lsattr
	$(ROMFSINST) -E CONFIG_USER_E2FSPROGS_MISC_MKE2FS $(STAGEDIR)/sbin/mke2fs /sbin/mke2fs
	rm -f $(ROMFSDIR)/bin/mke2fs.ext2 $(ROMFSDIR)/bin/mke2fs.ext3
	$(ROMFSINST) -E CONFIG_USER_E2FSPROGS_MISC_MKE2FS -s mke2fs /sbin/mkfs.ext2
	$(ROMFSINST) -E CONFIG_USER_E2FSPROGS_MISC_MKE2FS -s mke2fs /sbin/mkfs.ext3
	$(ROMFSINST) -E CONFIG_USER_E2FSPROGS_MISC_MKLOST_FOUND $(STAGEDIR)/sbin/mklost+found /sbin/mklost+found
	$(ROMFSINST) -E CONFIG_USER_E2FSPROGS_MISC_TUNE2FS $(STAGEDIR)/sbin/tune2fs /sbin/tune2fs
	$(ROMFSINST) -E CONFIG_USER_E2FSPROGS_MISC_E2LABEL -s e2label /sbin/tune2fs
	$(ROMFSINST) -E CONFIG_USER_E2FSPROGS_MISC_UUIDGEN $(STAGEDIR)/bin/uuidgen /bin/uuidgen
