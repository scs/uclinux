## Process this file with automake to produce Makefile.in

# let make re-run automake upon need
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = m4 pixmaps po ipkg oRTP gsmlib mediastreamer2\
		media_api exosip coreapi console gnome share


EXTRA_DIST = config.rpath   linphone2.glade BUGS linphone.kdevprj \
				intltool-extract.in	\
				intltool-merge.in	\
				intltool-update.in \
				README.arm \
				autogen.sh \
				linphone.spec.in linphone.spec
ACLOCAL_FLAGS=-I$(top_srcdir)/m4

DISTCLEANFILES= intltool-extract intltool-merge intltool-update po/stamp-it po/.intltool-merge-cache

# `make rpm'

all-local: linphone.spec
linphone.spec: linphone.spec.in

.phony: rpm
rpm:
	$(MAKE) dist
# begin: rpmbuild weirdness
# - use only the first .spec in the archive...
# - if .spec.in comes first, build only .src.rpm
# ... so make sure linphone.spec comes before the others.
	-rm -f $(PACKAGE)-$(VERSION).tar
	gunzip $(PACKAGE)-$(VERSION).tar.gz
	tar --delete --file=$(PACKAGE)-$(VERSION).tar	\
		$(PACKAGE)-$(VERSION)/oRTP/ortp.spec.in	\
		$(PACKAGE)-$(VERSION)/oRTP/ortp.spec
	mkdir -p $(PACKAGE)-$(VERSION)/oRTP
	cp $(PACKAGE).spec* $(PACKAGE)-$(VERSION)/
	tar --append --file=$(PACKAGE)-$(VERSION).tar	\
		$(PACKAGE)-$(VERSION)/linphone.spec	\
		$(PACKAGE)-$(VERSION)/linphone.spec.in
	cp oRTP/ortp.spec* $(PACKAGE)-$(VERSION)/oRTP/
	tar --append --file=$(PACKAGE)-$(VERSION).tar	\
		$(PACKAGE)-$(VERSION)/oRTP/ortp.spec.in
	rm -rf $(PACKAGE)-$(VERSION)
	gzip $(PACKAGE)-$(VERSION).tar
	rpmbuild -ta --clean --rmsource --rmspec $(PACKAGE)-$(VERSION).tar.gz
# end: rpmbuild weirdness
#	rpmbuild -ta $(PACKAGE)-$(VERSION).tar.gz
