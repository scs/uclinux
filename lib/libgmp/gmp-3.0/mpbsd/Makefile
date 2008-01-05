
.EXPORT_ALL_VARIABLES:

# VPATH = $(ROOTDIR)/freeswan/gmp/mpbsd
CFLAGS += -I../../$(LIBCDIR)/include
srcdir = $(ROOTDIR)/lib/libgmp/mpbsd

MPBSD_LINKS = add.c cmp.c gcd.c mul.c pow_ui.c  powm.c sqrtrem.c sub.c
MPBSD_SRCS = itom.c mdiv.c mfree.c min.c mout.c move.c mtox.c sdiv.c xtom.c \
  realloc.c $(MPBSD_LINKS)

MPBSD_OBJS = itom.o mdiv.o mfree.o min.o mout.o move.o mtox.o sdiv.o xtom.o \
  realloc.o add.o cmp.o gcd.o mul.o pow_ui.o powm.o sqrtrem.o sub.o

INCLUDES = -I. -I.. -I$(srcdir)/../mpz -I../mpn -I$(srcdir)/..
CFLAGS += -DBERKELEY_MP

libmpbsd.a: Makefile.in $(MPBSD_OBJS)
	rm -f $@
	$(AR) cr $@ $(MPBSD_OBJS)

clean:
	rm -f *.o libmpbsd.a

H = $(srcdir)/../gmp.h $(srcdir)/../gmp-impl.h ../mpn/gmp-mparam.h
L = $(srcdir)/../longlong.h

itom.o: $(srcdir)/itom.c ../mp.h $(H)
mdiv.o: $(srcdir)/mdiv.c ../mp.h $(H) $(L) $(srcdir)/../mpz/dmincl.c
mfree.o: $(srcdir)/mfree.c ../mp.h $(H)
min.o: $(srcdir)/min.c ../mp.h $(H)
mout.o: $(srcdir)/mout.c ../mp.h $(H)
move.o: $(srcdir)/move.c ../mp.h $(H)
mtox.o: $(srcdir)/mtox.c ../mp.h $(H)
sdiv.o: $(srcdir)/sdiv.c ../mp.h $(H) $(L)
xtom.o: $(srcdir)/xtom.c ../mp.h $(H)
add.o: $(srcdir)/../mpz/add.c $(H)
cmp.o: $(srcdir)/../mpz/cmp.c $(H)
gcd.o: $(srcdir)/../mpz/gcd.c $(H) $(L)
mul.o: $(srcdir)/../mpz/mul.c $(H)
pow_ui.o: $(srcdir)/../mpz/pow_ui.c $(H) $(L)
powm.o: $(srcdir)/../mpz/powm.c $(H) $(L)
realloc.o: $(srcdir)/realloc.c $(H)
sqrtrem.o: $(srcdir)/../mpz/sqrtrem.c $(H)
sub.o: $(srcdir)/../mpz/sub.c $(H)

