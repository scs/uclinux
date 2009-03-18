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
	../$${VER}/configure $(CONFIGURE_OPTS) --with-ao=$(STAGEDIR)/usr/lib/libao.so --with-ao-libraries=$(STAGEDIR)/usr/lib/ --with-ao-includes=$(STAGEDIR)/usr/include/ --disable-nls

clean:
	rm -rf build-*

romfs:
	$(ROMFSINST) -d ./build-vorbis-tools-1.2.0/oggdec/oggdec /usr/bin/oggdec
	$(ROMFSINST) -d ./build-vorbis-tools-1.2.0/ogg123/ogg123 /usr/bin/ogg123
	$(ROMFSINST) -d ./build-vorbis-tools-1.2.0/vorbiscomment/vorbiscomment /usr/bin/vorbiscomment
	$(ROMFSINST) -d ./build-vorbis-tools-1.2.0/oggenc/oggenc /usr/bin/oggenc
	$(ROMFSINST) -d ./build-vorbis-tools-1.2.0/ogginfo/ogginfo /usr/bin/ogginfo

.PHONY: all clean romfs
