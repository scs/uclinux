
include ../MCONFIG

PROGS=		resize2fs
TEST_PROGS=	test_extent

RESIZE_OBJS= extent.o resize2fs.o main.o sim_progress.o 

TEST_EXTENT_OBJS= extent.o test_extent.o

LIBS= $(LIBEXT2FS) $(LIBCOM_ERR)  
DEPLIBS= $(LIBEXT2FS) $(LIBCOM_ERR)

all: $(PROGS) $(TEST_PROGS) $(MANPAGES) 

resize2fs: $(RESIZE_OBJS) $(DEPLIBS)
	$(CC) $(LDFLAGS) -o resize2fs $(RESIZE_OBJS) $(LIBS) $(LDLIBS)

test_extent: $(TEST_EXTENT_OBJS)
	$(CC) $(LDFLAGS) -o test_extent $(TEST_EXTENT_OBJS) $(LIBS) $(LDLIBS)

romfs:
	
clean:
	$(RM) -f $(PROGS) $(TEST_PROGS) $(MANPAGES) \#* *.gdb *.s *.o *.a *~ core \
		resize2fs.static test_extent.out

$(RESIZE_OBJS) $(TEST_EXTENT_OBJS): ../MCONFIG
