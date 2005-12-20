OPROFILE_PATH=$(PWD)
BINUTILS_PATH=$(CONFIG_USER_BINUTILS)
BINUTILS_FLAG= -I$(BINUTILS_PATH)/bfd -I$(BINUTILS_PATH)/intl -I$(BINUTILS_PATH)/libiberty -I$(BINUTILS_PATH)/include -L$(BINUTILS_PATH)/bfd -L$(BINUTILS_PATH)/intl -L$(BINUTILS)/libiberty -lbfd -lintl -liberty


BINUTILS_CONFIG_ARG=--build=i386-pc-linux-gnu --host=bfin-uclinux --target=bfin-uclinux
BINUTILS_LO_CFLAGS="-I$(ROOTDIR)/lib/gmp -I$(ROOTDIR)/lib/mpfr -L$(ROOTDIR)/lib/gmp/.libs -L$(ROOTDIR)/lib/mpfr"


LO_CFLAGS=  -I${ROOTDIR}/lib/popt -L${ROOTDIR}/lib/popt/.libs/  $(BINUTILS_FLAG) 

LO_CXXFLAGS= -I${ROOTDIR}/lib/popt -L${ROOTDIR}/lib/popt/.libs  $(BINUTILS_FLAG)

LO_LDFLAGS= -Wl,-elf2flt

CONFIGURE_SETTINGS := --with-kernel-support --build=i386-pc-linux-gnu --host=bfin-uclinux --prefix=${ROMFSDIR}/usr


silly_thingy: Makefile
	
	make -f Makefile
Makefile:
	make -f makefile binutils
	unset LDFLAGS CC CFLAGS && \
			CFLAGS="$(LO_CFLAGS)" CXXFLAGS="$(LO_CXXFLAGS)" LDFLAGS="$(LO_LDFLAGS)" ./configure $(CONFIGURE_SETTINGS)

romfs:
	make -f Makefile install

clean:
	make -f Makefile distclean
%: Makefile
	make -f Makefile $@
binutils:$(BINUTILS_PATH)/Makefile $(BINUTILS_PATH)/bfd/Makefile $(BINUTILS_PATH)/intl/Makefile $(BINUTILS_PATH)/libiberty/Makefile
	make -C $(BINUTILS_PATH)/bfd/
	make -C $(BINUTILS_PATH)/intl/
	make -C $(BINUTILS_PATH)/libiberty/
$(BINUTILS_PATH)/Makefile:
	cd $(BINUTILS_PATH);CFLAGS=$(BINUTILS_LO_CFLAGS) ./configure $(BINUTILS_CONFIG_ARG); cd $(OPROFILE_PATH)
$(BINUTILS_PATH)/bfd/Makefile:
	 cd $(BINUTILS_PATH)/bfd; CFLAGS=$(BINUTILS_LO_CFLAGS) ./configure $(BINUTILS_CONFIG_ARG); cd $(OPROFILE_PATH)
$(BINUTILS_PATH)/intl/Makefile:
	 cd $(BINUTILS_PATH)/intl;  CFLAGS=$(BINUTILS_LO_CFLAGS) ./configure $(BINUTILS_CONFIG_ARG); cd $(OPROFILE_PATH)
$(BINUTILS_PATH)/libiberty/Makefile:
	cd $(BINUTILS_PATH)/libiberty; CFLAGS=$(BINUTILS_LO_CFLAGS) ./configure $(BINUTILS_CONFIG_ARG); cd $(OPROFILE_PATH)


