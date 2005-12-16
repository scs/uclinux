silly_thingy: Makefile
	make -f Makefile

LO_CFLAGS= -Wl,-elf2flt  

LO_CXXFLAGS=  -Wl,-elf2flt 

CONFIGURE_SETTINGS :=  --build=i386-pc-linux-gnu --host=bfin-uclinux


Makefile:
	unset LDFLAGS CC CFLAGS && \
			CFLAGS="$(LO_CFLAGS)" CXXFLAGS="$(LO_CXXFLAGS)" ./configure $(CONFIGURE_SETTINGS)

romfs:
	make -f Makefile install

clean:
	make -f Makefile distclean

%: Makefile
	make -f Makefile $@

