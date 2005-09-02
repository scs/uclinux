
# -*- sh -*-

# $Id$
MY_CFLAGS = -I/usr/include -I.
BUILD_CFLAGS += $(MY_CFLAGS)
BUILD_CC = gcc
CFLAGS += -D__USE_BSD -I$(ROOTDIR)/lib/zlib -I.

TARGETS = ftl_format flash_erase flash_eraseall nanddump doc_loadbios \
	mkfs.jffs ftl_check mkfs.jffs2 flash_lock flash_unlock flash_info \
	flash_otp_info flash_otp_dump mtd_debug flashcp nandwrite \
	jffs2dump \
	nftldump nftl_format docfdisk \
	rfddump rfdformat \
	#jffs2reader 

BUILD_TARGETS = $(patsubst %,build/%,$(TARGETS))

SYMLINKS = 
JFFS2_OBJS = crc32.o mkfs.jffs2.o compr_zlib.o compr_rtime.o compr.o
ERASEALL_OBJS = crc32.o flash_eraseall.o
DUMP_OBJS = crc32.o jffs2dump.o

ifeq ($(LINUXDIR),linux-2.2.x)
SYMLINKS += compr_rubin.h compr_rubin.c compr.c histo_mips.h pushpull.h pushpull.c
JFFS2_OBJS += compr_rubin.o compr.o pushpull.o
endif

BUILD_JFFS2_OBJS = $(patsubst %,build/%,$(JFFS2_OBJS))
BUILD_ERASEALL_OBJS = $(patsubst %,build/%,$(ERASEALL_OBJS))
BUILD_DUMP_OBJS = $(patsubst %,build/%,$(DUMP_OBJS))


all: build $(TARGETS) $(BUILD_TARGETS)

.PHONY:
build:
	[ -d build ] || mkdir build

clean:
	rm -f *.o *.gdb $(TARGETS) $(BUILD_TARGETS) $(SYMLINKS)
	rm -rf build

romfs:
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_ERASE        /bin/flash_erase
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_ERASEALL     /bin/flash_eraseall
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_FTL_CHECK    /bin/ftl_check
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_FTL_FORMAT   /bin/ftl_format
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_MKFSJFFS     /bin/mkfs.jffs
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_MKFSJFFS2    /bin/mkfs.jffs2
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NFTLDUMP     /bin/nftldump
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NFTL_FORMAT  /bin/nftl_format
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NANDDUMP     /bin/nanddump
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NANDTEST     /bin/nandtest
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_NANDWRITE    /bin/nandwrite
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_DOC_LOADBIOS /bin/doc_loadbios
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_DOC_LOADIPL  /bin/doc_loadipl

mkfs.jffs2.o crc32.o: crc32.h
build/mkfs.jffs2.o build/crc32.o: crc32.h
compr_rubin.o: pushpull.h
build/compr_rubin.o: pushpull.h
compr_rubin.o: histo_mips.h compr_rubin.h
build/compr_rubin.o: histo_mips.h compr_rubin.h

$(SYMLINKS):
	ln -sf $(ROOTDIR)/$(LINUXDIR)/fs/jffs2/$@ $@

mkfs.jffs2: $(JFFS2_OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ $(LDPATH) -lz $(LDLIBS)

build/mkfs.jffs2: $(BUILD_JFFS2_OBJS)
	$(BUILD_CC) -o $@ $^ -lz

flash_eraseall: $(ERASEALL_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
build/flash_eraseall: $(BUILD_ERASEALL_OBJS)
	$(BUILD_CC) -o $@ $^ 

jffs2reader: jffs2reader.o
	$(CC) $(LDFLAGS) -o $@ $^ -lz 

jffs2dump: $(DUMP_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
build/jffs2dump: $(BUILD_DUMP_OBJS)
	$(BUILD_CC) -o $@ $^

build/%.o: %.c
	$(BUILD_CC) $(BUILD_CFLAGS) -c -o $@ $<

build/%: %.c
	$(BUILD_CC) $(BUILD_CFLAGS) -o $@ $<
