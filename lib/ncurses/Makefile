ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
NCURSES_SHARED = --with-shared
else
NCURSES_SHARED = --without-shared
endif

all: build/Makefile
	$(MAKE) -C build install DESTDIR=$(STAGEDIR)

build/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure \
		$(CONFIGURE_OPTS) \
		$(NCURSES_SHARED) \
		--disable-termcap \
		--without-ada \
		--with-manpage-format=normal \
		--with-manpage-renames=no \
		--with-manpage-aliases=no \
		--with-manpage-symlinks=no \
		--enable-symlinks \
		--enable-const

clean:
	rm -rf build

romfs:
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libncurses.so.5 /lib/
	mkdir -p $(ROMFSDIR)/usr/share/terminfo
	tic -x -s -e linux,vt100 -o $(ROMFSDIR)/usr/share/terminfo/ misc/terminfo.src

.PHONY: all clean romfs
