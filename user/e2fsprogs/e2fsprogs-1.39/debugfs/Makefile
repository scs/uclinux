
include ../MCONFIG

PROGS = debugfs

DEBUG_OBJS= debug_cmds.o debugfs.o util.o ncheck.o icheck.o ls.o \
	lsdel.o dump.o setsuper.o logdump.o

LIBS= $(LIBEXT2FS) $(LIBE2P) $(LIBSS) $(LIBCOM_ERR)  $(LIBUUID)
DEPLIBS= $(LIBEXT2FS) $(LIBE2P) $(LIBSS) $(LIBCOM_ERR)  $(DEPLIBUUID)
MK_CMDS=	_SS_DIR_OVERRIDE=../lib/ss ../lib/ss/mk_cmds

all: $(PROGS)

debugfs: $(DEBUG_OBJS) $(DEPLIBS)
	$(CC) $(LDFLAGS) -o debugfs $(DEBUG_OBJS) $(LIBS) $(LDLIBS)

debug_cmds.c debug_cmds.h: debug_cmds.ct
	$(MK_CMDS) $(srcdir)/debug_cmds.ct

romfs:
	$(ROMFSINST) -e CONFIG_USER_E2FSPROGS_DEBUGFS_DEBUGFS /bin/debugfs

clean:
	$(RM) -f debugfs debugfs.8 \#* *.gdb *.s *.o *.a *~ debug_cmds.c core

$(DEBUG_OBJS): ../MCONFIG
