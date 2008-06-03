VER = directvnc-0.7.5

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure $(CONFIGURE_OPTS) $(CONF_OPTS)
	ln -s $(ROOTDIR)/user/microwin/nxlib/nxlib-0.45/X11/include/X11 build-$(VER)/

clean:
	rm -rf build*

romfs:
	$(ROMFSINST) -d build-$(VER)/src/directvnc /usr/bin/directvnc

.PHONY: all clean romfs
