
include ../../MCONFIG

COMPILE_ET=../et/compile_et
MK_CMDS=_SS_DIR_OVERRIDE=. ./mk_cmds
CFLAGS += -DPOSIX_SIGNALS -I$(srcdir)/../et

OBJS=	ss_err.o \
	std_rqs.o \
	invocation.o help.o \
	execute_cmd.o listen.o parse.o error.o prompt.o \
	request_tbl.o list_rqs.o pager.o requests.o \
	data.o
LIBRARY = ../libss.a

all: $(LIBRARY)

$(LIBRARY): $(OBJS)
	$(AR) rcv $@ $(OBJS)
	-$(RANLIB) $@

std_rqs.c: std_rqs.ct mk_cmds
	DIR=$(srcdir) $(MK_CMDS) $(srcdir)/std_rqs.ct

ss_err.c ss_err.h: ss_err.et
	$(COMPILE_ET) $(srcdir)/ss_err.et

mk_cmds: $(DEP_SUBSTITUTE) $(srcdir)/mk_cmds.sh.in
	$(SUBSTITUTE) $(srcdir)/mk_cmds.sh.in mk_cmds
	$(CHMOD) +x mk_cmds

clean:
	$(RM) -f ../libss.a libss.a mk_cmds ss_err.h ss_err.c std_rqs.c \
		*.o *.gdb *~ \#* *.bak core 

$(OBJS): ../../MCONFIG
