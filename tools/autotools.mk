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

	$(ROOTDIR)/tools/cross-fix-root

post-build::

ifneq ($(findstring s,$(MAKEFLAGS)),)
echo-cmd = :
else
echo-cmd = printf
endif

if_changed = \
	@echo $(CONFIGURE_OPTS) $(CONF_OPTS) $(CFLAGS) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) > .build-$(VER).settings.new ; \
	if ! cmp -s .build-$(VER).settings.new .build-$(VER).settings ; then \
		$(echo-cmd) "%s\n" "$(cmd_$(1))" ; \
		( $(cmd_$(1)) ) || exit $$? ; \
	fi ; \
	mv .build-$(VER).settings.new .build-$(VER).settings

cmd_configure = \
	set -e ; \
	chmod a+rx $(VER)/configure ; \
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure $(CONFIGURE_OPTS) $(CONF_OPTS)
build-$(VER)/Makefile: FORCE
	$(call if_changed,configure)

clean:
	rm -rf build* .build*

.PHONY: all clean post-build romfs FORCE

#
# Helper functions
#

# $(call USE_ENABLE,LIB_FFMPEG,video) => --enable-video if LIB_FFMPEG is set
USE_ENABLE = $(shell test "$(CONFIG_$(1))" = "y" && echo "--enable-$(2)" || echo "--disable-$(2)")
