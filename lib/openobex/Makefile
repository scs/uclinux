VER = openobex-1.3.0

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	mkdir build-$(VER)/src ; \
	cp $(VER)/src/irda.h build-$(VER)/src/irda.h ; \
	cd build-$(VER) ; \
	../$(VER)/configure \
		$(CONFIGURE_OPTS)

clean:
	rm -rf build*

.PHONY: all clean romfs
