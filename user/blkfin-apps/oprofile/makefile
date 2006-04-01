OPROFILE_PATH=$(PWD)
BINUTILS_PATH=$(CONFIG_USER_BINUTILS)
BINUTILS_BUILD_PATH=$(CONFIG_USER_BINUTILS_BUILD)
BINUTILS_FLAG=-lbfd -liberty


BINUTILS_LO_CFLAGS="-I$(ROOTDIR)/lib/gmp -I$(ROOTDIR)/lib/mpfr -L$(ROOTDIR)/lib/gmp/.libs -L$(ROOTDIR)/lib/mpfr"


LO_CFLAGS=  -I${ROOTDIR}/lib/popt -L${ROOTDIR}/lib/popt/.libs/  $(BINUTILS_FLAG) 

LO_CXXFLAGS= -I${ROOTDIR}/lib/popt -L${ROOTDIR}/lib/popt/.libs  $(BINUTILS_FLAG)

LO_LDFLAGS= -Wl,-elf2flt

CONFIGURE_SETTINGS := --with-kernel-support --build=i386-pc-linux-gnu --host=bfin-uclinux --prefix=${ROMFSDIR}/usr


silly_thingy: Makefile
	make -f Makefile
Makefile:
	unset LDFLAGS CC CFLAGS && \
			CFLAGS="$(LO_CFLAGS)" CXXFLAGS="$(LO_CXXFLAGS)" LDFLAGS="$(LO_LDFLAGS)" ./configure $(CONFIGURE_SETTINGS)

romfs:
	make -f Makefile install
	cp ./bfin_opcontrol $(ROMFSDIR)/usr/bin

clean:
	make -f Makefile distclean
%: Makefile
	make -f Makefile $@


