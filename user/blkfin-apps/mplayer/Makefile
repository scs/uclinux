VER = MPlayer-svn-23293

all: $(VER)/config.mak
	$(MAKE) -C $(VER)

$(VER)/config.mak:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	cd $(VER) ; \
	./configure \
		--enable-cross-compile \
		--target=$(CONFIGURE_HOST) \
		--host-cc=gcc \
		--cc=$(CONFIGURE_HOST)-gcc \
		--as=$(CONFIGURE_HOST)-as \
		--prefix=/usr \
		--confdir=/etc \
		--mandir=/usr/share/man \
		--enable-fbdev \
		--disable-mp3lib

clean:
	-$(MAKE) -C $(VER) distclean

romfs:
	$(ROMFSINST) -d $(VER)/mplayer /usr/bin/mplayer
	$(ROMFSINST) -d $(VER)/mencoder /usr/bin/mencoder

.PHONY: all clean romfs
