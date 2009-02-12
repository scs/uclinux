include_HEADERS = \
	rtdk.h

nodist_include_HEADERS=$(CONFIG_HEADER)

SUBDIRS = \
	asm-generic \
	asm-blackfin \
	asm-x86 \
	asm-ia64 \
	asm-powerpc \
	asm-arm \
	asm-sim \
	native \
	nucleus \
	posix \
	psos+ \
	rtai \
	rtdm \
	uitron \
	vrtx \
	vxworks

install-data-local:
	rm -f $(DESTDIR)$(includedir)/asm
	$(LN_S) asm-@XENO_TARGET_ARCH@ $(DESTDIR)$(includedir)/asm
	rm -f $(DESTDIR)$(includedir)/xenomai
	$(LN_S) . $(DESTDIR)$(includedir)/xenomai
	rm -f $(DESTDIR)$(includedir)/asm-@XENO_TARGET_ARCH@/xenomai
	$(LN_S) . $(DESTDIR)$(includedir)/asm-@XENO_TARGET_ARCH@/xenomai
	rm -f $(DESTDIR)$(includedir)/asm-generic/xenomai
	$(LN_S) . $(DESTDIR)$(includedir)/asm-generic/xenomai

uninstall-local:
	rm -f $(DESTDIR)$(includedir)/asm
	rm -f $(DESTDIR)$(includedir)/xenomai
	rm -f $(DESTDIR)$(includedir)/asm-@XENO_TARGET_ARCH@/xenomai
	rm -f $(DESTDIR)$(includedir)/asm-generic/xenomai

dist-hook:
	find $(distdir)/compat -name .svn -depth -exec rm -fr \{\} \;

EXTRA_DIST = compat
