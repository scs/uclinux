
.EXPORT_ALL_VARIABLES:

# VPATH = $(ROOTDIR)/freeswan/gmp/mpq
CFLAGS += -I../../$(LIBCDIR)/include
srcdir = $(ROOTDIR)/lib/libgmp/mpq

MPQ_SRCS = add.c canonicalize.c clear.c cmp.c cmp_ui.c div.c get_d.c \
 get_den.c get_num.c init.c inv.c mul.c neg.c set.c set_den.c set_num.c \
 set_si.c set_ui.c sub.c equal.c set_z.c
MPQ_OBJS = add.o canonicalize.o clear.o cmp.o cmp_ui.o div.o get_d.o \
 get_den.o get_num.o init.o inv.o mul.o neg.o set.o set_den.o set_num.o \
 set_si.o set_ui.o sub.o equal.o set_z.o

INCLUDES = -I. -I.. -I../mpn -I$(srcdir)/..

CFLAGS += $(INCLUDES)

libmpq.a: Makefile $(MPQ_OBJS)
	rm -f $@
	$(AR) cr $@ $(MPQ_OBJS)

clean:
	rm -f *.o libmpq.a

H = $(srcdir)/../gmp.h $(srcdir)/../gmp-impl.h ../mpn/gmp-mparam.h

add.o: $(srcdir)/add.c $(H)
canonicalize.o: $(srcdir)/canonicalize.c $(H)
clear.o: $(srcdir)/clear.c $(H)
cmp.o: $(srcdir)/cmp.c $(H) $(srcdir)/../longlong.h
cmp_ui.o: $(srcdir)/cmp_ui.c $(H)
div.o: $(srcdir)/div.c $(H)
equal.o: $(srcdir)/equal.c $(H)
get_d.o: $(srcdir)/get_d.c $(H) $(srcdir)/../longlong.h
get_den.o: $(srcdir)/get_den.c $(H)
get_num.o: $(srcdir)/get_num.c $(H)
init.o: $(srcdir)/init.c $(H)
inv.o: $(srcdir)/inv.c $(H)
mul.o: $(srcdir)/mul.c $(H)
neg.o: $(srcdir)/neg.c $(H)
set.o: $(srcdir)/set.c $(H)
set_den.o: $(srcdir)/set_den.c $(H)
set_num.o: $(srcdir)/set_num.c $(H)
set_si.o: $(srcdir)/set_si.c $(H)
set_ui.o: $(srcdir)/set_ui.c $(H)
set_z.o: $(srcdir)/set_z.c $(H)
sub.o: $(srcdir)/sub.c $(H)

