silly_thingy: Makefile
	make -f Makefile

LO_CFLAGS= -I${ROOTDIR}/lib/bfd -I${ROOTDIR}/lib/popt -L${ROOTDIR}/lib/popt/.libs/ -I${ROOTDIR}/lib/libiberty/binutils/include/ -L$(ROOTDIR)/lib/libiberty/ -L${ROOTDIR}/lib/bfd/ -L${ROOTDIR}/lib/intl -lintl -liberty -Wl,-elf2flt  

LO_CXXFLAGS= -I${ROOTDIR}/lib/popt -I${ROOTDIR}/lib/bfd -I../../../lib/popt -I${ROOTDIR}/lib/bfd/binutils/include/ -liberty -L$(ROOTDIR)/lib/libiberty/ -L${ROOTDIR}/lib/bfd/ -L${ROOTDIR}/lib/intl -L${ROOTDIR}/lib/popt/.libs -lintl  -Wl,-elf2flt 

CONFIGURE_SETTINGS := --with-kernel-support --build=i386-pc-linux-gnu --host=bfin-uclinux --prefix=${ROMFSDIR}/usr


Makefile:
	unset LDFLAGS CC CFLAGS && \
			CFLAGS="$(LO_CFLAGS)" CXXFLAGS="$(LO_CXXFLAGS)" ./configure $(CONFIGURE_SETTINGS)

romfs:
	make -f Makefile install

clean:
	make -f Makefile distclean

%: Makefile
	make -f Makefile $@

