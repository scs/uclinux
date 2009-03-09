# Requirements:
# - set VER to the package directory
# - define romfs target
# Optional:
# - set CONF_OPTS
#
# Then just add to your package Makefile:
# include $(ROOTDIR)/tools/autotools.mk

all: build-$(VER)/Makefile $(AUTOTOOLS_ALL_DEPS)
	$(MAKE) pre-build
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)
	$(MAKE) post-build

	$(ROOTDIR)/tools/cross-fix-root

pre-build::
post-build::

include $(ROOTDIR)/tools/download.mk

ifneq ($(findstring s,$(MAKEFLAGS)),)
echo-cmd = :
else
echo-cmd = printf
endif

if_changed = \
	settings="build-$(3)$(VER)/.dist.settings" ; \
	echo $(2) $(CFLAGS) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) > .new.settings ; \
	if ! cmp -s .new.settings $$settings ; then \
		$(echo-cmd) "%s\n" "$(cmd_$(1))" ; \
		( $(cmd_$(1)) ) || exit $$? ; \
	fi ; \
	mv .new.settings $$settings

cmd_configure = \
	set -e ; \
	chmod a+rx $(VER)/configure ; \
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure ; \
	rm -rf build-$(3)$(VER) ; \
	mkdir build-$(3)$(VER) ; \
	cd build-$(3)$(VER) ; \
	../$(VER)/configure $(2)
build-$(VER)/Makefile: build-host-$(VER)/Makefile FORCE
	@$(call if_changed,configure,$(CONFIGURE_OPTS) $(CONF_OPTS))

build-host-$(VER)/Makefile: FORCE
ifeq ($(AUTOTOOLS_BUILD_HOST),true)
	@export AR="" CC=$(HOSTCC) CXX="" LD="" RANLIB="" \
		CPPFLAGS="" CFLAGS="-O2 -g" CXXFLAGS="-O2 -g" LDFLAGS="" CONFIG_SITE="" \
	$(call if_changed,configure,$(BUILD_CONFIGURE_OPTS) $(BUILD_CONF_OPTS),host-)
	$(MAKE) host-build
endif

clean:
	rm -rf build* .build*

.PHONY: all clean pre-build post-build romfs FORCE

#
# Helper functions
#

# $(call _USE_CONF,enable,disable,LIB_FFMPEG,video,blah) -> --enable-video=blah if LIB_FFMPEG
# $(call _USE_CONF,with,without,LIB_FFMPEG,video)        -> --with-video if LIB_FFMPEG
_USE_CONF = $(shell \
	opt="$(5)"; test "$${opt:+set}" = "set" && opt="=$${opt}"; \
	test "$(CONFIG_$(3))" = "y" \
		&& echo "--$(1)-$(4)$${opt}" \
		|| echo "--$(2)-$(4)")

# $(call USE_ENABLE,LIB_FFMPEG,video) => --enable-video if LIB_FFMPEG is set
USE_ENABLE = $(call _USE_CONF,enable,disable,$(1),$(2),$(3))

# $(call USE_WITH,LIB_FFMPEG,video) => --with-video if LIB_FFMPEG is set
USE_WITH = $(call _USE_CONF,with,without,$(1),$(2),$(3))
