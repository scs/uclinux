VER = dosfstools-3.0.2

CPPFLAGS += -D_FILE_OFFSET_BITS=64

TARGETS-y :=
TARGETS-$(CONFIG_USER_DOSFSTOOLS_MKDOSFS) += dosfsck
TARGETS-$(CONFIG_USER_DOSFSTOOLS_DOSFSCK) += mkdosfs

all:
	$(MAKE) -C $(VER) OPTFLAGS= $(TARGETS-y)

clean:
	$(MAKE) -C $(VER) distclean
	rm -f $(VER)/*.gdb

romfs:
	$(ROMFSINST) -e CONFIG_USER_DOSFSTOOLS_MKDOSFS $(VER)/mkdosfs /sbin/mkdosfs
	$(ROMFSINST) -e CONFIG_USER_DOSFSTOOLS_MKDOSFS -s mkdosfs /sbin/mkfs.msdos
	$(ROMFSINST) -e CONFIG_USER_DOSFSTOOLS_MKDOSFS -s mkdosfs /sbin/mkfs.vfat

	$(ROMFSINST) -e CONFIG_USER_DOSFSTOOLS_DOSFSCK $(VER)/dosfsck /sbin/dosfsck
	$(ROMFSINST) -e CONFIG_USER_DOSFSTOOLS_DOSFSCK -s dosfsck /sbin/fsck.msdos
	$(ROMFSINST) -e CONFIG_USER_DOSFSTOOLS_DOSFSCK -s dosfsck /sbin/fsck.vfat

.PHONY: all clean romfs
