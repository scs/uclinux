VER = ncurses-5.6

NCURSES_TERMS = linux,vt100,vt220,xterm
NCURSES_DEMOS = dots firework gdc hanoi newdemo railroad rain tclock worm xmas

CONF_OPTS = \
	$(CONFIGURE_SHARED_ENABLE) \
	--disable-termcap \
	--without-ada \
	--with-manpage-format=normal \
	--with-manpage-renames=no \
	--with-manpage-aliases=no \
	--with-manpage-symlinks=no \
	--enable-symlinks \
	--enable-const

include $(ROOTDIR)/tools/autotools.mk

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
