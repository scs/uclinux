# -*- sh -*-

# $Id$

#
# These flags are used for build native versions of the tools for the
# host system so it can generate images etc
#
MY_CFLAGS = -I/usr/include -I.
BUILD_CFLAGS += $(MY_CFLAGS)
BUILD_CC = gcc
CFLAGS += -D__USE_BSD -I.

TARGETS_$(CONFIG_USER_MTDUTILS_ERASE)		+= erase
TARGETS_$(CONFIG_USER_MTDUTILS_ERASEALL)	+= eraseall
TARGETS_$(CONFIG_USER_MTDUTILS_FTL_CHECK)	+= ftl_check
TARGETS_$(CONFIG_USER_MTDUTILS_FTL_FORMAT)	+= ftl_format
TARGETS_$(CONFIG_USER_MTDUTILS_NFTL_FORMAT)	+= nftl_format
TARGETS_$(CONFIG_USER_MTDUTILS_NFTLDUMP)	+= nftldump
TARGETS_$(CONFIG_USER_MTDUTILS_NANDDUMP)	+= nanddump
TARGETS_$(CONFIG_USER_MTDUTILS_NANDTEST)	+= nandtest
TARGETS_$(CONFIG_USER_MTDUTILS_NANDWRITE)	+= nandwrite
TARGETS_$(CONFIG_USER_MTDUTILS_DOC_LOADBIOS)	+= doc_loadbios
TARGETS_$(CONFIG_USER_MTDUTILS_DOC_LOADIPL)	+= doc_loadipl
TARGETS_$(CONFIG_USER_MTDUTILS_MKFSJFFS)	+= mkfs.jffs
TARGETS_$(CONFIG_USER_MTDUTILS_MKFSJFFS2)	+= mkfs.jffs2

# Host based builds needed for constructing host images
TARGETS_$(CONFIG_JFFS_FS)			+= build/mkfs.jffs
TARGETS_$(CONFIG_JFFS2_FS)			+= build/mkfs.jffs2


SYMLINKS = 
JFFS2_OBJS = crc32.o mkfs.jffs2.o compr_zlib.o compr_rtime.o

ifeq ($(LINUXDIR),linux-2.2.x)
SYMLINKS += compr_rubin.h compr_rubin.c compr.c histo_mips.h pushpull.h pushpull.c
JFFS2_OBJS += compr_rubin.o compr.o pushpull.o
endif

BUILD_JFFS2_OBJS = $(patsubst %,build/%,$(JFFS2_OBJS))

all: build $(TARGETS_y)

.PHONY:
build:
	[ -d build ] || mkdir build

clean:
	rm -f $(TARGETS_y) $(TARGETS_n) $(TARGETS_m) $(TARGETS_) $(SYMLINKS)
	rm -f *.o *.gdb
	rm -rf build

romfs:
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_ERASE        /bin/erase
	$(ROMFSINST) -e CONFIG_USER_MTDUTILS_ERASEALL     /bin/eraseall
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

doc_loadipl: doc_loadipl.o rsencode.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ $(LDPATH) $(LDLIBS)

build/doc_loadipl: build/doc_loadipl.o build/rsencode.o
	$(BUILD_CC) -o $@ $^

compr.o: compr.c
	$(CC) $(CFLAGS) -Dprintk=printf -DKERN_NOTICE= -DKERN_WARNING= -c -o $@ $<

build/compr.o: compr.c
	$(BUILD_CC) $(BUILD_CFLAGS) -Dprintk=printf -DKERN_NOTICE= -DKERN_WARNING= -c -o $@ $<

compr_zlib.o: compr_zlib.c
	$(CC) $(CFLAGS) -c -o $@ $<

build/compr_zlib.o: compr_zlib.c
	$(BUILD_CC) $(BUILD_CFLAGS) -Dprintk=printf -DKERN_NOTICE= -DKERN_WARNING= -c -o $@ $<

jffs2reader: jffs2reader.c
	$(CC) $(LDFLAGS) $(CFLAGS) jffs2reader.c -o jffs2reader $(LDPATH) -lz $(LDLIBS)

build/jffs2reader: jffs2reader.c
	$(BUILD_CC) $(BUILD_CFLAGS) -o $@ $< -lz

build/%.o: %.c
	$(BUILD_CC) $(BUILD_CFLAGS) -c -o $@ $<

build/%: %.c
	$(BUILD_CC) $(BUILD_CFLAGS) -o $@ $<

