
EXTRA_DIST=mediastreamer-config.h.in pkg.list autogen.sh mediastreamer.pc.in mediastreamer2.spec.in mediastreamer2.spec

SUBDIRS=src build include tests plugins

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = mediastreamer.pc

## oRTP packaging methods:

# `make rpm'

.phony: rpm

rpm:
	$(MAKE) dist
	rpmbuild -ta $(PACKAGE)-$(VERSION).tar.gz

# `make package'

if WITH_EPM

.PHONY: package

PKG_NAME = $(PACKAGE)-$(VERSION)-$(RELEASE)
BUILDROOT=`pwd`/epm-install

package: $(srcdir)/pkg.list $(srcdir)/configure
	[ -n "$(BUILDROOT)" ] && rm -rf $(BUILDROOT)/*
	[ -n "$(PKG_NAME).*" ] && rm -f $(PKG_NAME).*
	$(MAKE) install DESTDIR=$(BUILDROOT)
	$(MKEPMLIST) -u $(SYS_USER) -g $(SYS_GROUP) --prefix $(prefix) \
		$(BUILDROOT)/$(prefix) > files.list
	$(EPM) -v -f native -g -n -a $(ARCH) --keep-files --output-dir pkg \
		srcdir=$(srcdir) \
		top_srcdir=$(top_srcdir) \
		top_builddir=$(top_builddir) \
		PACKAGE=$(PACKAGE) \
		SUMMARY="$(SUMMARY)" \
		VERSION=$(ORTP_PKGCONFIG_VERSION) \
		RELEASE=$(RELEASE) \
		LICENSE="$(LICENSE)" \
		VENDOR="$(VENDOR)" \
		PACKAGER="$(PACKAGER)" \
		$(PACKAGE) $(srcdir)/pkg.list
	rm -rf $(BUILDROOT)
	mv -f pkg/$(PACKAGE)-$(ORTP_PKGCONFIG_VERSION)-$(RELEASE).$(EPM_PKG_EXT) $(PKG_NAME).$(ARCH).$(EPM_PKG_EXT)

clean-local:
	rm -rf pkg $(BUILDROOT)
	rm -f files.list

endif WITH_EPM
