silly_thingy: Makefile
	make -f Makefile

CONFIGURE_SETTINGS :=  --build=i386-pc-linux-gnu --host=bfin-uclinux


Makefile:
	unset LDFLAGS CC CFLAGS; \
	CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)" LDFLAGS="$(LDFLAGS)" \
		./configure $(CONFIGURE_SETTINGS)

romfs:
	echo "nothing for romfs"

clean:
	make -f Makefile distclean

%: Makefile
	make -f Makefile $@
