
.EXPORT_ALL_VARIABLES:

# VPATH = $(ROOTDIR)/freeswan/gmp/mpn
CFLAGS += -I../../$(LIBCDIR)/include
srcdir = $(ROOTDIR)/lib/libgmp/mpn

MPN_OBJECTS = add_n.o addmul_1.o addsub_n.o bdivmod.o bz_divrem_n.o cmp.o \
	diveby3.o divmod_1.o divrem.o divrem_1.o divrem_2.o dump.o gcd.o gcd_1.o \
	gcdext.o get_str.o hamdist.o inlines.o lshift.o mod_1.o mul.o mul_1.o \
	mul_basecase.o mul_n.o perfsqr.o popcount.o pre_mod_1.o random.o \
	random2.o rshift.o sb_divrem_mn.o scan0.o scan1.o set_str.o \
	sqr_basecase.o sqrtrem.o sub_n.o submul_1.o tdiv_qr.o udiv_w_sdiv.o

INCLUDES = -I. -I.. -I$(srcdir) -I$(srcdir)/..

CFLAGS += $(INCLUDES)

libmpn.a: Makefile mp_bases.o $(MPN_OBJECTS)
	rm -f $@
	$(AR) cr $@ mp_bases.o $(MPN_OBJECTS)

gmp-mparam.h:
	echo "#include \"$(srcdir)/generic/gmp-mparam.h\"" > gmp-mparam.h

vpath %.c $(srcdir)/generic

clean:
	rm -f *.o tmp-* libmpn.a gmp-mparam.h

# Maybe configure could add dependencies here..?

H = $(srcdir)/../gmp.h $(srcdir)/../gmp-impl.h gmp-mparam.h
L = $(srcdir)/../longlong.h

mp_bases.o: $(srcdir)/mp_bases.c $(H)
bdivmod.o: bdivmod.c $(H) $(L)
cmp.o: cmp.c $(H)
divmod_1.o: divmod_1.c $(H) $(L)
divrem.o: divrem.c $(H) $(L)
divrem_1.o: divrem_1.c $(H) $(L)
dump.o: dump.c $(H)
gcd.o: gcd.c $(H) $(L)
gcd_1.o: gcd_1.c $(H) $(L)
gcdext.o: gcdext.c $(H) $(L)
get_str.o: get_str.c $(H) $(L)
hamdist.o: hamdist.c $(H)
inlines.o: inlines.c $(srcdir)/../gmp.h
mod_1.o: mod_1.c $(H) $(L)
mul.o: mul.c $(H)
mul_n.o: mul_n.c $(H)
perfsqr.o: perfsqr.c $(H) $(L)
popcount.o: popcount.c $(H)
pre_mod_1.o: pre_mod_1.c $(H) $(L)
random2.o: random2.c $(H)
scan0.o: scan0.c $(H) $(L)
scan1.o: scan1.c $(H) $(L)
set_str.o: set_str.c $(H)
sqrtrem.o: sqrtrem.c $(H) $(L)

