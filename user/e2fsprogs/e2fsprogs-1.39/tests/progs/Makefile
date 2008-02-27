
include ../../MCONFIG

MK_CMDS=	_SS_DIR_OVERRIDE=../../lib/ss ../../lib/ss/mk_cmds

PROGS=		test_icount

TEST_REL_OBJS=	test_rel.o test_rel_cmds.o

TEST_ICOUNT_OBJS=	test_icount.o test_icount_cmds.o

LIBS= $(LIBEXT2FS) $(LIBSS) $(LIBCOM_ERR)
DEPLIBS= $(LIBEXT2FS) $(LIBSS) $(LIBCOM_ERR)

all: $(PROGS)

test_rel: $(TEST_REL_OBJS) $(DEPLIBS)
	$(CC) $(LDFLAGS) -o test_rel $(TEST_REL_OBJS) $(LIBS) $(LDLIBS)

test_rel_cmds.c: test_rel_cmds.ct
	$(MK_CMDS) $(srcdir)/test_rel_cmds.ct

test_icount: $(TEST_ICOUNT_OBJS) $(DEPLIBS)
	$(CC) $(LDFLAGS) -o test_icount $(TEST_ICOUNT_OBJS) $(LIBS) $(LDLIBS)

test_icount_cmds.c: test_icount_cmds.ct
	$(MK_CMDS) $(srcdir)/test_icount_cmds.ct

romfs:

clean:
	$(RM) -f $(PROGS) test_rel_cmds.c test_icount_cmds.c \
		\#* *.s *.gdb *.o *.a *~ core

$(TEST_REL_OBJS) $(TEST_ICOUNT_OBJS): ../../MCONFIG
