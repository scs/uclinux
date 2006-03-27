# build and install

silly_thingy: Makefile
	
	make -f Makefile
Makefile:
	CC=bfin-uclinux-gcc CFLAGS="-DBFIN" LDFLAGS="-Wl,-elf2flt" ./configure --host=bfin-linux --build=i386-linux --prefix=${ROMFSDIR}/usr;
romfs:
	make -f Makefile install
clean:
	make -f Makefile distclean
%: Makefile
	make -f Makefile $@
