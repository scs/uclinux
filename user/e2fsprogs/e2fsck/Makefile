
include ../MCONFIG

PROGS = e2fsck

#
# Flags for doing mtrace --- uncomment to produce mtracing e2fsck
# 	Note:  The optimization flags must include -g
#
#MTRACE=	-DMTRACE
#MTRACE_OBJ= mtrace.o

OBJS= unix.o e2fsck.o super.o pass1.o pass1b.o pass2.o pass3.o pass4.o \
	pass5.o journal.o swapfs.o badblocks.o util.o dirinfo.o ehandler.o \
	problem.o message.o recovery.o region.o revoke.o ea_refcount.o \
	$(MTRACE_OBJ)

CFLAGS +=	-DRESOURCE_TRACK

LIBS    = $(LIBEXT2FS) $(LIBCOM_ERR) $(LIBUUID)
DEPLIBS = $(LIBEXT2FS) $(LIBCOM_ERR) $(DEPLIBUUID)

all: $(PROGS)

e2fsck: $(OBJS) $(DEPLIBS)
	$(CC) $(LDFLAGS) -o e2fsck $(OBJS) $(LIBS) $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_E2FSCK_E2FSCK /bin/e2fsck

clean:
	$(RM) -f $(PROGS) \#* *\# *.gdb *.s *.o *.a *~ core e2fsck.static \
		e2fsck.shared e2fsck.profiled flushb e2fsck.8
	$(RM) -rf profiled

$(OBJS): ../MCONFIG
