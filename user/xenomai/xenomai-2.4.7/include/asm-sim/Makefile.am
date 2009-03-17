includesubdir = $(includedir)/asm-sim

includesub_HEADERS = system.h

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(includesubdir)
	rm -f $(DESTDIR)$(includesubdir)/asm
	$(LN_S) . $(DESTDIR)$(includesubdir)/asm
	rm -f $(DESTDIR)$(includesubdir)/xenomai
	$(LN_S) . $(DESTDIR)$(includesubdir)/xenomai

uninstall-local:
	rm -f $(DESTDIR)$(includesubdir)/asm
	rm -f $(DESTDIR)$(includesubdir)/xenomai

SUBDIRS = bits
