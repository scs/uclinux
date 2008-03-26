VER = strace-4.5.15

FLTFLAGS = -s 20000

all: build-$(VER)/Makefile .check
	$(MAKE) -C build-$(VER)

# don't fail in a release, just in a scm
.check:
	if ! BUILD_CC=gcc ./check-entities.sh $(ROOTDIR)/$(LINUXDIR) $(ARCH) $(VER) $(MACHINE) ; then [ -d .svn ] && exit 1 ; fi
	touch check

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure $(CONFIGURE_OPTS) $(CONF_OPTS)

clean:
	rm -rf build* check

romfs:
	$(ROMFSINST) build-$(VER)/strace /bin/strace
	$(ROMFSINST) -e CONFIG_USER_PERL_PERL build-$(VER)/strace-graph /bin/strace-graph

.PHONY: all clean romfs
