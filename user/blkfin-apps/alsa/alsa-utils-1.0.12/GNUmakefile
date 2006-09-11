ALSA_VER := $(shell cat version)

all: Makefile
	$(MAKE) -f Makefile
	$(MAKE) -f Makefile install DESTDIR=$$PWD/DESTDIR

Makefile:
	./configure \
		--host=bfin-uclinux \
		--prefix=/usr \
		--with-alsa-prefix=$$PWD/../alsa-lib-$(ALSA_VER)/DESTDIR/usr/lib \
		--with-alsa-inc-prefix=$$PWD/../alsa-lib-$(ALSA_VER)/DESTDIR/usr/include

%::
	if [ -f Makefile ] ; then $(MAKE) -f Makefile $@ || exit $$? ; fi
