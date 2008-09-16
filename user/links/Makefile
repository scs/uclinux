DIRS = $(dir $(wildcard */configure))

DIRS_makefiles = $(patsubst %,build-%/Makefile,$(DIRS))

all: $(DIRS_makefiles)
	for d in $(DIRS) ; do $(MAKE) -C build-$$d || exit $$? ; done

%/Makefile:
	set -e ; \
	VER=$(patsubst build-%/Makefile,%,$@) ; \
	find $${VER} -type f -print0 | xargs -0 touch -r $${VER}/configure ; \
	rm -rf build-$${VER} ; \
	mkdir build-$${VER} ; \
	cd build-$${VER} ; \
	DIRECTFB_CONFIG=$(STAGEDIR)/usr/bin/directfb-config \
	../$${VER}/configure $(CONFIGURE_OPTS) --without-x --enable-graphics

clean:
	rm -rf build-*

romfs:
	$(ROMFSINST) build-links-2.1pre32/links /bin/links
.PHONY: all clean romfs
