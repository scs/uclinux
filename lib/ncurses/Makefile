VER = ncurses-5.7

NCURSES_TERMS = linux,vt100,vt220,xterm
NCURSES_DEMOS = dots firework gdc hanoi newdemo railroad rain tclock worm xmas

CONF_OPTS = \
	$(CONFIGURE_SHARED_WITH) \
	--disable-termcap \
	--without-ada \
	--with-manpage-format=normal \
	--with-manpage-renames=no \
	--with-manpage-aliases=no \
	--with-manpage-symlinks=no \
	--enable-symlinks \
	--enable-const

AUTOTOOLS_BUILD_HOST = true
BUILD_CONF_OPTS = \
	--disable-termcap \
	--without-ada \
	--disable-shared \
	--enable-static
export PATH := $(ROOTDIR)/lib/ncurses/build-host-$(VER)/progs:$(PATH)

include $(ROOTDIR)/tools/autotools.mk

host-build:
	$(MAKE) -C build-host-$(VER)/include
	$(MAKE) -C build-host-$(VER)/progs tic

post-build::
ifeq ($(CONFIG_USER_NCURSES_TESTS),y)
	$(MAKE) -C build-$(VER)/test
endif

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
