VER = w3cam-0.7.2

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure $(CONFIGURE_OPTS)

clean:
	rm -rf build*

romfs:
	$(ROMFSINST) -d build-$(VER)/vidcat /usr/bin/vidcat
	$(ROMFSINST) -d build-$(VER)/w3cam /usr/bin/w3cam
	$(ROMFSINST) -d build-$(VER)/w3camd/w3camd /usr/sbin/w3camd

.PHONY: all clean romfs
