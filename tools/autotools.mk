# Requirements:
# - set VER to the package directory
# - define romfs target
# Optional:
# - set CONF_OPTS
#
# Then just add to your package Makefile:
# include $(ROOTDIR)/tools/autotools.mk

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)
	$(MAKE) post-build

# fix library perms, mung paths in pkg-config files, libtool linker scripts,
# and random -config scripts to point to our build directory, and cross-compile
# symlinks for the -config scripts as autotool packages will search for
# prefixed -config scripts when cross-compiling.  note: the ugly ln/mv is to
# work around a possible race condition if multiple make jobs are generating
# the same symlink at the same time.  a `mv` is "atomic" (it uses rename())
# while a `ln` is actually unlink();symlink();.
	set -e; \
	cd $(STAGEDIR); \
	find ./usr/lib/ -name 'lib*.so*' -print0 | xargs -0 -r chmod 755; \
	find ./usr/lib/ -name 'lib*.la' -o -name 'lib*.a' -print0 | xargs -0 -r chmod 644; \
	find ./usr/lib/ -name 'lib*.la' -print0 | xargs -0 -r sed -i "/^libdir=/s:=.*:='$(STAGEDIR)/usr/lib':"; \
	find ./usr/lib/pkgconfig/ -name '*.pc' -print0 | xargs -0 -r sed -i "/^prefix=/s:=.*:='$(STAGEDIR)/usr':"; \
	find ./usr/bin/ -name '*-config' -print0 | xargs -0 -r sed -i "/^prefix=/s:=.*:='$(STAGEDIR)/usr':"; \
	cd usr/bin; \
	for config in *-config ; do \
		ln -s "$(STAGEDIR)/usr/bin/$$config" "$(ROOTDIR)/tools/$(CROSS_COMPILE)$$config.$$$$"; \
		mv "$(ROOTDIR)/tools/$(CROSS_COMPILE)$$config.$$$$" "$(ROOTDIR)/tools/$(CROSS_COMPILE)$$config"; \
	done 

post-build::

build-$(VER)/Makefile:
	chmod a+rx $(VER)/configure # for CVS users with screwed perms
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure $(CONFIGURE_OPTS) $(CONF_OPTS)

clean:
	rm -rf build*

.PHONY: all clean post-build romfs

#
# Helper functions
#

# $(call USE_ENABLE,LIB_FFMPEG,video) => --enable-video if LIB_FFMPEG is set
USE_ENABLE = $(shell test "$(CONFIG_$(1))" = "y" && echo "--enable-$(2)" || echo "--disable-$(2)")
