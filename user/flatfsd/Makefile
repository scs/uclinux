-include ../user.mak

######################################################

VERSION = 3.0.1

######################################################

EXEC = flatfsd
OBJS = flatfsd.o newfs.o reboot.o

# force error checking on compile
CFLAGS += -Wall -Werror

# CFLAGS += -DDEBUG

######################################################
#
# Erk! settings to change the way flatfsd works
#
# Explicit setting overrides autodetect
USING_FLASH_FILESYSTEM_$(CONFIG_USER_FLATFSD_USE_FLASH_FS) = y
USING_DISKLIKE_DEVICE_$(CONFIG_USER_FLATFSD_DISKLIKE) = y
ifdef CONFIG_USER_FLATFSD_AUTO
	ifdef CONFIG_NFTL
		ifndef CONFIG_MTD_CFI_INTELEXT
			USING_DISKLIKE_DEVICE_$(CONFIG_SH_SECUREEDGE5410) = y
		endif
	endif
	ifeq ($(USING_DISKLIKE_DEVICE_y),)
		USING_MTD_DEVICE_$(CONFIG_MTD) = y
		USING_BLKMEM_DEVICE_$(CONFIG_BLK_DEV_BLKMEM) = y
	endif
endif

ifdef CONFIG_USER_FLATFSD_COMPRESSED
	OBJS += flatfs3.o
	EXTRA_LIBS = -lz
endif

######################################################

ifdef USING_DISKLIKE_DEVICE_y
CFLAGS += -DUSING_DISKLIKE_DEVICE=1
OBJS += flatfs.o flatfs1.o disk.o ops.o
SUBSYS = disk
else
ifdef USING_MTD_DEVICE_y
CFLAGS += -DUSING_MTD_DEVICE=1
OBJS += flatfs.o flatfs1.o mtd.o ops.o
SUBSYS = mtd
else
ifdef USING_BLKMEM_DEVICE_y
CFLAGS += -DUSING_BLKMEM_DEVICE=1
OBJS += flatfs.o flatfs1.o blkmem.o ops.o
SUBSYS = blkmem
else
ifdef USING_FLASH_FILESYSTEM_y
CFLAGS += -DUSING_FLASH_FILESYSTEM=1
SUBSYS = fs
else
all:: ERROR-no-flatfsd-storage-type-defined
endif
endif
endif
endif

ifdef CONFIG_PROP_LOGD_LOGD
CFLAGS += -DLOGGING
endif
ifdef CONFIG_USER_FLATFSD_HAS_RTC
CFLAGS += -DHAS_RTC
endif

CFLAGS += -DFLATFSD_VERSION='"$(VERSION)$(SUBSYS)"'

######################################################

all:: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(EXTRA_LIBS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

######################################################

$(OBJS): Makefile flatfs.h

######################################################
