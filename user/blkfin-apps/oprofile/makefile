OPROFILE_PATH=$(PWD)
BINUTILS_PATH=$(CONFIG_USER_BINUTILS)
BINUTILS_BUILD_PATH=$(CONFIG_USER_BINUTILS_BUILD)
BINUTILS_FLAG= -I$(BINUTILS_PATH)/bfd -I$(BINUTILS_PATH)/intl -I$(BINUTILS_PATH)/libiberty -I$(BINUTILS_PATH)/include -L$(BINUTILS_BUILD_PATH)/bfd -L$(BINUTILS_BUILD_PATH)/intl -L$(BINUTILS_BUILD_PATH)/libiberty -lbfd -lintl -liberty


BINUTILS_CONFIG_ARG=--build=i386-pc-linux-gnu --host=bfin-uclinux --target=bfin-uclinux
BINUTILS_LO_CFLAGS="-I$(ROOTDIR)/lib/gmp -I$(ROOTDIR)/lib/mpfr -L$(ROOTDIR)/lib/gmp/.libs -L$(ROOTDIR)/lib/mpfr"


LO_CFLAGS=  -I${ROOTDIR}/lib/popt -L${ROOTDIR}/lib/popt/.libs/  $(BINUTILS_FLAG) 

LO_CXXFLAGS= -I${ROOTDIR}/lib/popt -L${ROOTDIR}/lib/popt/.libs  $(BINUTILS_FLAG)

LO_LDFLAGS= -Wl,-elf2flt

CONFIGURE_SETTINGS := --with-kernel-support --build=i386-pc-linux-gnu --host=bfin-uclinux --prefix=${ROMFSDIR}/usr


silly_thingy: Makefile
	
	make -f Makefile
Makefile:
	mkdir $(BINUTILS_BUILD_PATH); cd $(BINUTILS_BUILD_PATH);CFLAGS=$(BINUTILS_LO_CFLAGS) $(BINUTILES_PATH)/configure $(BINUTILS_CONFIG_ARG); cd $(OPROFILE_PATH);
	mkdir $(BINUTILS_BUILD_PATH)/bfd;cd $(BINUTILS_BUILD_PATH)/bfd; CFLAGS=$(BINUTILS_LO_CFLAGS) $(BINUTILES_PATH)/configure $(BINUTILS_CONFIG_ARG); cd $(OPROFILE_PATH)
	mkdir $(BINUTILS_BUILD_PATH)/intl;cd $(BINUTILS_BUILD_PATH)/intl;  CFLAGS=$(BINUTILS_LO_CFLAGS) $(BINUTILES_PATH)/configure $(BINUTILS_CONFIG_ARG); cd $(OPROFILE_PATH)
	mkdir $(BINUTILS_BUILD_PATH)/libiberty;cd $(BINUTILS_BUILD_PATH)/libiberty; CFLAGS=$(BINUTILS_LO_CFLAGS) $(BINUTILES_PATH)/configure $(BINUTILS_CONFIG_ARG); cd $(OPROFILE_PATH)
	make -C $(BINUTILS_BUILD_PATH)/bfd/
	make -C $(BINUTILS_BUILD_PATH)/intl/
	make -C $(BINUTILS_BUILD_PATH)/libiberty/
	unset LDFLAGS CC CFLAGS && \
			CFLAGS="$(LO_CFLAGS)" CXXFLAGS="$(LO_CXXFLAGS)" LDFLAGS="$(LO_LDFLAGS)" ./configure $(CONFIGURE_SETTINGS)

romfs:
	make -f Makefile install
	cp ./bfin_opcontrol $(ROMFSDIR)/usr/bin

clean:
	make -f Makefile distclean
%: Makefile
	make -f Makefile $@


