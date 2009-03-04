VER = readline-6.0
URL = ftp://ftp.gnu.org/gnu/readline/$(VER).tar.gz

CONF_OPTS = \
	$(CONFIGURE_SHARED_ENABLE) \
	--with-curses

# readline always needs a terminal library.  by default, it does not link with
# any so that it can be swapped out depending on the application.  but in the
# Linux world, the only relevant package is ncurses.  all the other termcap
# libraries either suck or simply don't exist.  so force linking of ncurses to
# avoid issues otherwise.
LDFLAGS += -lncurses

include $(ROOTDIR)/tools/autotools.mk

pre-build::
	$(MAKE) -C build-$(VER)

post-build::
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
	$(MAKE) -C build-$(VER) install-shared DESTDIR=$(STAGEDIR)
endif
	rm -f $(STAGEDIR)/usr/lib/*.old

romfs:
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libreadline.so.6 /lib/
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libhistory.so.6 /lib/
