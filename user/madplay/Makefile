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
	../$${VER}/configure $(CONFIGURE_OPTS) --without-x

clean:
	rm -rf build-*

romfs:
	$(ROMFSINST) -d ./build-madplay-0.15.2b/madplay /usr/bin/madplay

.PHONY: all clean romfs
