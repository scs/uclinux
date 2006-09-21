ALSA_VER := $(shell sed -n '/AM_INIT_AUTOMAKE/s:.* \(.*\).$$:\1:p' configure.in)

all: Makefile
	$(MAKE) -f Makefile
	$(MAKE) -f Makefile install DESTDIR=$$PWD/DESTDIR

Makefile:
	LDFLAGS="-L$(ROOTDIR)/lib/ncurses/lib $(LDFLAGS)" \
	CPPFLAGS="-I$(ROOTDIR)/lib/ncurses/include $(CPPFLAGS)" \
	./configure \
		--host=bfin-uclinux \
		--prefix=/usr \
		--with-alsa-prefix=$$PWD/../alsa-lib-$(ALSA_VER)/DESTDIR/usr/lib \
		--with-alsa-inc-prefix=$$PWD/../alsa-lib-$(ALSA_VER)/DESTDIR/usr/include

%::
	if [ -f Makefile ] ; then $(MAKE) -f Makefile $@ || exit $$? ; fi
