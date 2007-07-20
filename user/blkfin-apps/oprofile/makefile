FLTFLAGS=-s 32000
CFLAGS += -I$(ROOTDIR)/lib/popt
CXXFLAGS += -I$(ROOTDIR)/lib/popt -fexceptions
LDFLAGS += -L$(ROOTDIR)/lib/popt/build/.libs

CONFOPTS = --with-kernel-support --prefix=/usr

all: build/Makefile
	$(MAKE) -C build install DESTDIR=$$PWD/DESTDIR
	-$(STRIPTOOL) $$PWD/DESTDIR/usr/bin/*

build/Makefile: makefile
	touch * */* */*/*
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure $(CONFIGURE_OPTS) $(CONFOPTS)

romfs:
	$(ROMFSINST) DESTDIR/usr/bin /usr/bin
	$(ROMFSINST) DESTDIR/usr/share/oprofile /usr/share/oprofile
	$(ROMFSINST) bfin_opcontrol /usr/bin

clean:
	rm -rf build DESTDIR
