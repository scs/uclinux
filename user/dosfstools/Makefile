VER = dosfstools-2.11

CFLAGS += -D_FILE_OFFSET_BITS=64

all clean:
ifeq ($(CONFIG_USER_DOSFSTOOLS_MKDOSFS),y)
	$(MAKE) -C $(VER)/mkdosfs $@
endif
ifeq ($(CONFIG_USER_DOSFSTOOLS_DOSFSCK),y)
	$(MAKE) -C $(VER)/dosfsck $@
endif

romfs:
	$(ROMFSINST) -e CONFIG_USER_DOSFSTOOLS_MKDOSFS $(VER)/mkdosfs/mkdosfs /sbin/mkdosfs
	$(ROMFSINST) -e CONFIG_USER_DOSFSTOOLS_MKDOSFS -s mkdosfs /sbin/mkfs.msdos
	$(ROMFSINST) -e CONFIG_USER_DOSFSTOOLS_MKDOSFS -s mkdosfs /sbin/mkfs.vfat

	$(ROMFSINST) -e CONFIG_USER_DOSFSTOOLS_DOSFSCK $(VER)/dosfsck/dosfsck /sbin/dosfsck
	$(ROMFSINST) -e CONFIG_USER_DOSFSTOOLS_DOSFSCK -s dosfsck /sbin/fsck.msdos
	$(ROMFSINST) -e CONFIG_USER_DOSFSTOOLS_DOSFSCK -s dosfsck /sbin/fsck.vfat

.PHONY: all clean romfs
