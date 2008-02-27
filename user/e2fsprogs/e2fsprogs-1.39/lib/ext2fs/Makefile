
include ../../MCONFIG

COMPILE_ET=../et/compile_et

DEBUGFS_LIB_OBJS = bb_compat.o cmp_bitmaps.o dupfs.o fileio.o \
	namei.o test_io.o write_bb_file.o 

RESIZE_LIB_OBJS = rs_bitmap.o

E2IMAGE_LIB_OBJS = imager.o

OBJS= \
	ext2_err.o \
	alloc.o \
	alloc_tables.o \
	badblocks.o \
	bb_inode.o \
	bitmaps.o \
	bitops.o \
	block.o \
	bmap.o \
	check_desc.o \
	closefs.o \
	dblist.o \
	dblist_dir.o \
	dirblock.o \
	dir_iterate.o \
	expanddir.o \
	ext_attr.o \
	finddev.o \
	flushb.o \
	freefs.o \
	gen_bitmap.o \
	get_pathname.o \
	getsize.o \
	icount.o \
	initialize.o \
	inline.o \
	inode.o \
	ismounted.o \
	link.o \
	llseek.o \
	lookup.o \
	mkdir.o \
	mkjournal.o \
	native.o \
	newdir.o \
	openfs.o \
	read_bb.o \
	read_bb_file.o \
	rw_bitmaps.o \
	swapfs.o \
	unix_io.o \
	unlink.o \
	valid_blk.o \
	version.o \
	$(DEBUGFS_LIB_OBJS) $(RESIZE_LIB_OBJS) $(E2IMAGE_LIB_OBJS)

LIBRARY = ../libext2fs.a

all: $(LIBRARY)

$(LIBRARY): $(OBJS)
	$(AR) rcv $@ $(OBJS)
	-$(RANLIB) $@

ext2_err.et: $(DEP_SUBSTITUTE) $(srcdir)/ext2_err.et.in
	$(SUBSTITUTE) $(srcdir)/ext2_err.et.in ext2_err.et

ext2_err.c ext2_err.h: ext2_err.et
	$(COMPILE_ET) ext2_err.et

tst_badblocks: tst_badblocks.o freefs.o \
		read_bb_file.o write_bb_file.o badblocks.o 
	$(CC) $(LDFLAGS) -o tst_badblocks tst_badblocks.o freefs.o \
		read_bb_file.o write_bb_file.o badblocks.o $(LIBCOM_ERR) $(LDLIBS)

tst_iscan: tst_iscan.o inode.o badblocks.o test_io.o $(LIBEXT2FS)
	$(CC) $(LDFLAGS) -o tst_iscan tst_iscan.o inode.o badblocks.o test_io.o \
		$(LIBEXT2FS) $(LIBCOM_ERR) $(LDLIBS)

tst_getsize: tst_getsize.o getsize.o $(LIBEXT2FS)
	$(CC) $(LDFLAGS) -o tst_getsize tst_getsize.o getsize.o $(LIBEXT2FS) \
		$(LIBCOM_ERR) $(LDLIBS)

tst_ismounted: $(srcdir)/ismounted.c $(LIBEXT2FS)
	$(CC) $(LDFLAGS) -o tst_ismounted $(srcdir)/ismounted.c -DDEBUG \
		$(ALL_CFLAGS) $(LIBCOM_ERR)  $(LDLIBS)

tst_byteswap: tst_byteswap.o bitops.o $(LIBEXT2FS)
	$(CC) $(LDFLAGS) -o tst_byteswap tst_byteswap.o bitops.o $(LIBEXT2FS) \
		$(LIBCOM_ERR) $(LDLIBS)

tst_bitops: tst_bitops.o inline.o $(LIBEXT2FS)
	$(CC) $(LDFLAGS) -o tst_bitops tst_bitops.o inline.o \
		$(LIBEXT2FS) $(LIBCOM_ERR) $(LDLIBS)

mkjournal: mkjournal.c $(LIBEXT2FS)
	$(CC) $(LDFLAGS) -o mkjournal $(srcdir)/mkjournal.c -DDEBUG \
		$(LIBEXT2FS) $(LIBCOM_ERR) $(ALL_CFLAGS) $(LDLIBS)

clean:
	$(RM) -f \#* *.gdb *.s *.o *.a *~ *.bak core profiled/* checker/* \
		tst_badblocks tst_iscan ext2_err.et ext2_err.c ext2_err.h \
		tst_byteswap tst_ismounted mkjournal \
		../libext2fs.a ../libext2fs_p.a ../libext2fs_chk.a

$(OBJS): ../../MCONFIG
