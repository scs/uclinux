VER = ncurses-5.6

NCURSES_TERMS = linux,vt100,vt220,xterm
NCURSES_DEMOS = dots firework gdc hanoi newdemo railroad rain tclock worm xmas

ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
NCURSES_SHARED = --with-shared
else
NCURSES_SHARED = --without-shared
endif

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)
ifeq ($(CONFIG_USER_NCURSES_TESTS),y)
	$(MAKE) -C build-$(VER)/test
endif

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure \
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
	rm -rf build*

romfs:
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libncurses.so.5 /lib/
	mkdir -p $(ROMFSDIR)/usr/share/terminfo
	tic -x -s -e $(NCURSES_TERMS) -o $(ROMFSDIR)/usr/share/terminfo/ $(VER)/misc/terminfo.src
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/tset /usr/bin/tset
	$(ROMFSINST) -s tset /usr/bin/reset

	set -e ; \
	for x in $(NCURSES_DEMOS) ; do \
		$(ROMFSINST) -e CONFIG_USER_NCURSES_TESTS build-$(VER)/test/$$x /bin/ncurses-demo-$$x ; \
	done

.PHONY: all clean romfs
